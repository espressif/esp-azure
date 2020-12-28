using Microsoft.Azure.Devices;
using System.Diagnostics;
using System.Threading;
using Microsoft.Azure.Devices.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.Azure.Devices.Shared;
using System.Drawing;

namespace RIoT
{
    class IoTDevice
    {
        internal bool FirmwareUpdateNeeded;

        DeviceClient Me;
        X509Certificate2 MyCert;
        string MyDevId;
        int CertCount;
        internal int DeviceNumber;
        internal string DeviceName;
        internal bool P0wned = false;

        internal bool HubRefreshNeeded;

        internal int CurrentFwVersionNumber;
        internal int DesiredFwVersionNumber;
        bool updateCurrentVersionNumber = true;

        int MessageCount;

        internal IoTDevice(string deviceName, int fwidSeed, int deviceNumber)
        {
            FirmwareUpdateNeeded = false;
            DeviceNumber = deviceNumber;
            DeviceName = deviceName;
            MyDevId = deviceName;
            CurrentFwVersionNumber = fwidSeed;
            HubRefreshNeeded = true;
            RefreshCert();
        }

        internal void RefreshCert()
        {
            Helpers.MakePFXFile(Program.ToPath(Program.AliasCert), Program.ToPath(Program.AliasKey), Program.ToPath(Program.AliasCertPFX), null);
            MyCert = new X509Certificate2(Program.ToPath(Program.AliasCertPFX));
            CertCount++;
        }

        internal bool RegisterWithFakeDRSServer()
        {
            SslTcpClient c = new SslTcpClient();
            bool connected = c.FakeDRSServerHandshake(MyDevId);
            if(connected)
            {
                HubRefreshNeeded = false;
            }
            return connected;
        }
        void QueryFWStatus()
        {
            try
            {
                var twin = Me.GetTwinAsync().Result;
                var myFwid = Helpers.Hexify(Helpers.HashData(new byte[] { (byte)CurrentFwVersionNumber }, 0, 1));
                var targetFwVersionNumber = twin.Properties.Desired["VersionNumber"];
                Int64 currentReportedVersionNumber = -1;
                if (twin.Properties.Reported.Contains("VersionNumber"))
                {
                    currentReportedVersionNumber = (Int64)twin.Properties?.Reported["VersionNumber"];
                }
                // update our version number if hub version number is not current
                if (    currentReportedVersionNumber < 0 || 
                        CurrentFwVersionNumber != currentReportedVersionNumber ||
                        updateCurrentVersionNumber
                        )
                {
                    TwinCollection t = new TwinCollection();
                    t["VersionNumber"] = CurrentFwVersionNumber;
                    Me.UpdateReportedPropertiesAsync(t).Wait();
                    updateCurrentVersionNumber = false;
                }
                // if the target version number is not current, then flag that we need a FW update
                if (targetFwVersionNumber != CurrentFwVersionNumber.ToString())
                {
                    FirmwareUpdateNeeded = true;
                    DesiredFwVersionNumber = targetFwVersionNumber;
                    Debug.WriteLine("Need to update myself");
                }
                else
                {
                    FirmwareUpdateNeeded = false;
                    Debug.WriteLine("Firmware version is good");
                }

                // am I p0wned?  If I'm P0wned I won't update myself
                if (twin.Properties.Desired.Contains("POwned"))
                {
                    P0wned = (bool)twin.Properties?.Desired["POwned"];
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine("Error querying status" + e.ToString());
                throw;

            }
            return;
        }
        Random rr = new Random();
        internal bool SendMessages(int numMessages, int sleepMilisecs)
        {
            var colors = Enum.GetValues(typeof(KnownColor));
            try
            {
                // Note that MQTT is required for the device twin stuff to work.
                Me = DeviceClient.Create(Program.IotHubUri, new DeviceAuthenticationWithX509Certificate(MyDevId, MyCert),
                    Microsoft.Azure.Devices.Client.TransportType.Mqtt);
                Me.OpenAsync().Wait();
                QueryFWStatus();
                for (byte j = 0; j < numMessages; j++)
                {
                    int colorVal = (int) colors.GetValue(rr.Next(colors.Length));
                    var t = Me.SendEventAsync(MakeMessage(MyDevId, colorVal, MessageCount++));
                    t.Wait();
                    Thread.Sleep(sleepMilisecs);
                }
                Me.CloseAsync().Wait();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in Create or SendMessages {ex.ToString()}");
                if(ex.InnerException!=null) Debug.WriteLine($"Error in SendMessages (inner exception is) {ex.InnerException.ToString()}");
                return false;
            }

            return true;
        }

        Microsoft.Azure.Devices.Client.Message MakeMessage(string devId, int colorVal, int messageCount)
        {
            var m = new
            {
                DevID = devId,
                ColorVal = colorVal,
                MessageCount = messageCount
            };
            var messageString = JsonConvert.SerializeObject(m);
            var message = new Microsoft.Azure.Devices.Client.Message(Encoding.ASCII.GetBytes(messageString));
            return message;
        }

    }
}
