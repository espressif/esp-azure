using Microsoft.Azure.Devices;
using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using RIoT;
using System.IO;
using Microsoft.Azure.Devices.Shared;
using Microsoft.ServiceBus.Messaging;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Digests;

namespace RIoTDemo
{
    /// <summary>
    /// Most program logic is driven from timer ticks in MainPage.  ChildStatus forms
    /// contain the per-device UI, but they display what they're told based on waht 
    /// goes on here.
    /// </summary>
    public partial class MainPage : Form
    {
        bool initialized = false;
        string  DeviceIDMatch = "RIoT_Test";
        string ControlDevice = "ControlDevice";
        byte[] ControlDeviceKey  = HashData(new byte[] { 0 } , 0,1);
        RegistryManager RegMgr;
        EventHubClient EventClient;
        EventHubReceiver[] Receivers;
        DateTime LastUpdateTime = DateTime.Now;
        string[] D2CPartitions;
        string ConnectionStringFile = "c:\\tmp\\ConnectionString.txt";
        //int CurrentFWVersionNumber = 0;
        IEnumerable<Device> CurrentDeviceList;
        List<DeviceStatus> StatusPanes = new List<DeviceStatus>();

        int TargetVersionNumber = 0;


        public MainPage()
        {
            InitializeComponent();
            TargetVersionNumber = 0;

        }

        bool paintBusy = false;
        private async void MainPage_Paint(object sender, PaintEventArgs e)
        {
            if (paintBusy) return;
            paintBusy = true;
            if (initialized) return;

            if (!File.Exists(ConnectionStringFile))
            {
                Notify($"Missing connection string file {ConnectionStringFile}.  This file is omitted from the distribution because it contains passwords. Fix and restart.");
                return;
            }
            try
            {
                var connectionString = File.ReadAllText(ConnectionStringFile);
                RegMgr = RegistryManager.CreateFromConnectionString(connectionString);
                string iotHubD2cEndpoint = "messages/events";
                EventClient = EventHubClient.CreateFromConnectionString(connectionString, iotHubD2cEndpoint);
                D2CPartitions = EventClient.GetRuntimeInformation().PartitionIds;
                Receivers = new EventHubReceiver[D2CPartitions.Length];
                for (int j = 0; j < D2CPartitions.Length; j++)
                {
                    Receivers[j] = EventClient.GetDefaultConsumerGroup().CreateReceiver(D2CPartitions[j], DateTime.UtcNow - new TimeSpan(0, 0, 10));
                }

                // make or refresh the control device (this is just a convenient way of passing 
                // data like the targetFWID from the GUI app to the server
                Device dTemplate = new Device(ControlDevice);
                dTemplate.Authentication = new AuthenticationMechanism();
                dTemplate.Authentication.SymmetricKey = new SymmetricKey();
                dTemplate.Authentication.SymmetricKey.PrimaryKey = Convert.ToBase64String(ControlDeviceKey);
                dTemplate.Authentication.SymmetricKey.SecondaryKey = Convert.ToBase64String(ControlDeviceKey);


                try
                {
                    await RegMgr.AddDeviceAsync(dTemplate);
                }
                catch(Exception zz)
                {
                    Helpers.Notify($"Failed to add device. Probably already exists.  Error is {zz.ToString()}");

                }


                try
                {
                    // and set the FWID property in the twin 
                    var props = new TwinCollection();
                    props["FWID"] = GetFWIDString(TargetVersionNumber);
                    props["VersionNumber"] = TargetVersionNumber.ToString();

                    var twin = await RegMgr.GetTwinAsync(ControlDevice);
                    twin.Properties.Desired = props;
                    await RegMgr.UpdateTwinAsync(ControlDevice, twin, twin.ETag);
                }
                catch (Exception ex)
                {
                    Helpers.Notify($"Failed to add device. Error is {ex.ToString()}");
                    return;
                }



                Debug.Write("");

                

                //CancellationTokenSource cts = new CancellationTokenSource();

            }
            catch (Exception ex)
            {
                Notify($"Failed to CreateFromConnectionString: {ex.ToString()}");
                return ;
            }
            // everything else happens on timer ticks
            this.timer1.Interval = 1000;
            this.timer1.Tick += Timer1_Tick;
            this.timer1.Start();
            initialized = true;
            paintBusy = false;

        }



        bool executing = false;
        private async void Timer1_Tick(object sender, EventArgs e)
        {
            if (executing) return;
            executing = true;
            // do we have changes to the devices we're monitoring?
            var devices = await RegMgr.GetDevicesAsync(100);
            var demoDevices = devices.Where(x => x.Id.Contains(DeviceIDMatch));
            if(DeviceListHasChanged(CurrentDeviceList, demoDevices))
            {
                CurrentDeviceList = demoDevices;
                UpdateDevicePanes();
            }
            // else update status of what we have

            // First, get a batch of messages and post them to the controls

            for (int j = 0; j < Receivers.Length; j++)
            {
                while (true)
                {

                    var mx = Receivers[j].Receive(new TimeSpan(0, 0, 0, 0, 1));
                    if (mx == null) break;
                    var senderDeviceId = mx.SystemProperties["iothub-connection-device-id"];
                    var messageData = mx.GetBytes();
                    var message = JsonConvert.DeserializeObject<MyMessageType>(Encoding.ASCII.GetString(messageData));

                    var device = StatusPanes.Where(x => x.Id == senderDeviceId.ToString()).First();
                    string colorString = Enum.GetName(typeof(KnownColor), message.ColorVal);
                    device.NotifyNewMessage($"Count={message.MessageCount}, Color = {colorString}");
                    device.PicColor = (KnownColor)message.ColorVal;
                    device.LastMessageTime = DateTime.Now;
                    Debug.WriteLine(message.ToString());
                }
            }


            // Next 1) update the background color based on what version number the device *claims* it is
            //      2) If device firmware is wrong AND the last firmware change was >1 min ago, revoke the
            //              creds for the device
            foreach (var cc in this.Controls)
            {
                if (!(cc is DeviceStatus)) continue;
                var ds = (DeviceStatus)cc;

                string deviceId = ds.Id;
                var device = demoDevices.Where(x => x.Id == deviceId).First();
                var twx = await RegMgr.GetTwinAsync(deviceId);
                CurrentState s = CurrentState.Good;
                DateTime nowTIme = DateTime.Now;
                try
                {
                    if (!twx.Properties.Reported.Contains("VersionNumber")) s = CurrentState.BadFirmware;
                    if (!twx.Properties.Desired.Contains("VersionNumber")) s = CurrentState.BadFirmware;
                    if (s != CurrentState.BadFirmware)
                    {
                        var reported = (twx.Properties.Reported["VersionNumber"]);
                        var desired = (twx.Properties.Desired["VersionNumber"]);
                        if (reported == desired)
                        {
                            s = CurrentState.Good;
                        }
                        else
                        { 
                            s = CurrentState.OldFirmware;
                        }
                        // If the device is out-of-date, and the update was requested >1 min ago, revoke the creds
                        if(s== CurrentState.OldFirmware && nowTIme-LastUpdateTime> new TimeSpan(0,1,0))
                        {
                            device.Authentication.X509Thumbprint.PrimaryThumbprint = null;
                            s = CurrentState.BadFirmware;
                            await RegMgr.UpdateDeviceAsync(device);
                        }

                        if (twx.Properties.Reported.Contains("VersionNumber"))
                        {
                            var repX = (twx.Properties.Reported["VersionNumber"]);
                            ds.MyVersionNumber = repX;
                        }
                    }
                }
                catch (Exception ee)
                {
                    Debug.WriteLine($"Error getting twin info {ee.ToString()}");
                    s = CurrentState.BadFirmware;
                }

                // any messages in the last minute?
                if (nowTIme - ds.LastMessageTime > new TimeSpan(0, 0, 1, 0))
                {
                    s = CurrentState.BadFirmware;
                }

                ds.State = s;
                ds.UpdateGUI();
            }

            // Finally, tell devices that they're P0wned
            foreach (var cc in this.Controls)
            {
                if (!(cc is DeviceStatus)) continue;
                var ds = (DeviceStatus)cc;
                if (!ds.P0wnedStatusChanged) continue;
                ds.P0wnedStatusChanged = false;

                var twx = await RegMgr.GetTwinAsync(ds.Id);

                TwinCollection t = new TwinCollection();
                t["POwned"] = ds.AmIPOwned;
                twx.Properties.Desired = t;
                await RegMgr.UpdateTwinAsync(ds.Id, twx, twx.ETag);

            }

            executing = false;

        }

        void UpdateDevicePanes()
        {
            // remove current
            foreach (var s in StatusPanes)
            {
                this.Controls.Remove(s);
            }
            StatusPanes.Clear();
            // this.Controls.Clear();
            // add new
            int xCount = 0;
            int yCount = 0;
            int yGutter = 64;
            foreach (var d in CurrentDeviceList)
            {
                DeviceStatus s = new DeviceStatus();
               
                s.Id = d.Id;
                if ((xCount + 1) * (s.Width + 10) + 10 > this.Width)
                {
                    yCount++;
                    xCount = 0;
                }
                s.Location = new Point(xCount * (s.Width + 10) + 10, yCount * (s.Height + 10) + yGutter);
                xCount++;
                s.Show();
                StatusPanes.Add(s);
                this.Controls.Add(s);
            }

        }

        bool DeviceListHasChanged(IEnumerable<Device> current, IEnumerable<Device> newList)
        {
            if (current == null) return true;
            if (current.Count() != newList.Count()) return true;
            foreach (var c in current)
            {
                if (newList.Where(x => x.Id == c.Id).Count() == 0) return true;
            }
            return false;
        }


        internal static void Notify(string s)
        {
            MessageBox.Show(s);
        }

        bool updating = false;
        private async void button1_Click(object sender, EventArgs e)
        {
            if (updating) return;
            updating = true;
            TargetVersionNumber++;
            this.VersionNumber.Text = $"Target Version Number {TargetVersionNumber}";

            try
            {
                // Set the FWID property in the twin 
                var props = new TwinCollection();
                props["FWID"] = GetFWIDString(TargetVersionNumber);
                props["VersionNumber"] = TargetVersionNumber.ToString();

                var twin = await RegMgr.GetTwinAsync(ControlDevice);
                twin.Properties.Desired = props;
                await RegMgr.UpdateTwinAsync(ControlDevice, twin, twin.ETag);
            }
            catch (Exception ex)
            {
                Helpers.Notify($"Failed to add device. Error is {ex.ToString()}");
                return;
            }


            /*

            var devices = await RegMgr.GetDevicesAsync(100);
            var demoDevices = devices.Where(x => x.Id.Contains(DeviceIDMatch));
            foreach(var d in demoDevices)
            {
                var twx = await RegMgr.GetTwinAsync(d.Id);

                TwinCollection t = new TwinCollection();
                t["VersionNumber"] = TargetVersionNumber;
                twx.Properties.Desired = t;
                await RegMgr.UpdateTwinAsync(d.Id, twx, twx.ETag);

            }
            */
            LastUpdateTime = DateTime.Now;
            updating = false;
        }

        /// <summary>
        /// SHA256 hash of data-fragment
        /// </summary>
        /// <param name="data"></param>
        /// <param name="start"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        internal static byte[] HashData(byte[] data, int start, int length)
        {
            var d = new Sha256Digest();
            d.BlockUpdate(data, start, length);
            var digest = new byte[32];
            d.DoFinal(digest, 0);
            return digest;
        }
        /// <summary>
        /// Convert a byte-array to packed HEX
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        public static string Hexify(byte[] t)
        {
            return BitConverter.ToString(t).Replace("-", "");
        }

        string GetFWIDString(int versionNumber)
        {
            return Hexify(HashData(new byte[] { (byte) versionNumber }, 0, 1));
        }


        void MakeControlDeviceTwin()
        {


        }


    }
    /*
            var m = new
            {
                DevID = devId,
                ColorVal = colorVal,
                MessageCount = messageCount
            };

    */
    public class MyMessageType
    {
        public string DevID;
        public int ColorVal;
        public int MessageCount;
    };

}
