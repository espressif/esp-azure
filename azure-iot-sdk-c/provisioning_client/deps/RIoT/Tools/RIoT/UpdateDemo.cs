using System;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RIoT
{

    /// <summary>
    /// Contains logic for a demo where a bunch of devices (right now just simulated devices, but easy to 
    /// extend to real devices) send messages to the hub and look for update requests, and then update themselves.
    /// 
    /// This test starts a TLS server with backing logic to create IoT device Hub instances.  This is the fake-DRS server
    /// 
    /// Devices are created that know the address of the fakeDRS server, but no hub twin.
    /// 
    /// When the devices start they connect to the fake-DRS service, and authenticate themselves usign their device certs
    ///
    /// If authentication is successful, the fake-DRS server creates the IoT hub device and sets the authentication 
    /// token as the alias cert.
    /// 
    /// 
    /// 
    /// </summary>
    class UpdateDemo
    {
        IoTDevice[] ClientDevices;
        internal static HubControl HubController;



        internal UpdateDemo()
        {
            HubController = new HubControl();
            HubController.Connect();
            HubController.RemoveAllDevices();
        }

        internal void FakeDRSTest()
        {
            int numDevices = 2;
            MakeClientDevicesAndCerts(numDevices);
            StartFakeDRSServerThread();
            RunDemo();
        }
        /// <summary>
        /// Make a bunch of IOTDevice objects and give them a name, keys and certs, but do not enroll them 
        /// in the hub
        /// </summary>
        /// <param name="numDevices"></param>
        void MakeClientDevicesAndCerts(int numDevices)
        {
            Program.IODir += "MultiDevice/";
            CertMaker m = new CertMaker(Program.IODir);

            ClientDevices = new IoTDevice[numDevices];
            // make the devices and enroll them in the hub
            for (int j = 0; j < numDevices; j++)
            {
                string devId = GetDeviceID(j);
                Program.SetDeviceNumber(j);

                // todo - have the devices chain to the same vendor root.
                int fwidSeed = 0;
                m.MakeNew(5, false, fwidSeed);
                IoTDevice device = new IoTDevice(devId, 0, j);
                ClientDevices[j] = device;
            }
        }

        void StartFakeDRSServerThread()
        {
            Task t = new Task(StartServer);
            t.Start();
        }
        void StartServer()
        {
            SslTcpServer.RunServer(
                  Program.ToPath(Program.ServerCA),
                  Program.ToPath(Program.ServerCert),
                  Program.ToPath(Program.ServerKey),
                  null,
                  null
                  );
        }
        void RunDemo()
        {
            while(true)
            {
                // tell the server what version number to look for
                int versionNumber = HubController.GetTargetVersionNumber();


                // register or re-register
                foreach (var d in ClientDevices)
                {
                    Program.SetDeviceNumber(d.DeviceNumber);
                    if (d.HubRefreshNeeded)
                    {
                        d.RegisterWithFakeDRSServer();
                    }
                }
                // try to send some messages
                foreach (var d in ClientDevices)
                {
                    Program.SetDeviceNumber(d.DeviceNumber);
                    d.SendMessages(1, 10);
                }
                // see if anyone needs to be updated
                foreach (var d in ClientDevices)
                {
                    Program.SetDeviceNumber(d.DeviceNumber);
                    if(d.FirmwareUpdateNeeded)
                    {
                        int targetFwid = d.DesiredFwVersionNumber;
                        d.CurrentFwVersionNumber = targetFwid;
                        if (!d.P0wned)
                        {
                            CertMaker m = new CertMaker(Program.IODir);
                            m.MakeNew(5, true, targetFwid);
                            d.FirmwareUpdateNeeded = false;
                            d.HubRefreshNeeded = true;
                            d.RefreshCert();
                        }
                        else
                        {
                            Debug.WriteLine($"I'm powned: {d.DeviceName}");
                        }
                    }
                }


                Thread.Sleep(1000);

                }

            }



        static internal void DoDemo(int numDevices)
        {
            Program.IODir += "MultiDevice/";
            CertMaker m = new CertMaker(Program.IODir);

            IoTDevice[] deviceList = new IoTDevice[numDevices];
            HubController = new HubControl();

            // make the devices and enroll them in the hub
            for (int j = 0; j < numDevices; j++)
            {
                string devId = GetDeviceID(j);
                Program.SetDeviceNumber(j);

                int fwidSeed = 0;
                m.MakeNew(5, false, fwidSeed);

                HubController.Connect();
                HubController.RemoveDevice(devId);

                var devInfo = ExtensionDecoder.Decode(Program.ToPath(Program.AliasCert));
                HubController.EnrollDevice(devId, fwidSeed, Helpers.Hexify(devInfo.FirmwareID), devInfo.Cert.Thumbprint);

                IoTDevice device = new IoTDevice(devId, 0, j);
                deviceList[j] = device;

            }

            // run through messaging and update
            bool[] primaryOrSEcondary = new bool[numDevices];
            int epoch = 0;
            while (true)
            {
                for (int j = 0; j < numDevices; j++)
                {
                    Program.SetDeviceNumber(j);
                    var device = deviceList[j];
                    string devId = GetDeviceID(j);

                    // send messages using current firmware
                    device.RefreshCert();
                    device.SendMessages(1, 30);

                    if (device.FirmwareUpdateNeeded)
                    {

                        // update the firmware on the device
                        int fwidSeed = device.DesiredFwVersionNumber;
                        m.MakeAliasCert(true, fwidSeed);
                        var devInfo = ExtensionDecoder.Decode(Program.ToPath(Program.AliasCert));

                        // and tell the hub
                        HubController.RefreshDevice(devId, fwidSeed, Helpers.Hexify(devInfo.FirmwareID), devInfo.Cert.Thumbprint, primaryOrSEcondary[j]);
                        primaryOrSEcondary[j] = !primaryOrSEcondary[j];
                        device.CurrentFwVersionNumber = fwidSeed;
                    }
                }
                Debug.WriteLine($"Epoch == {epoch++}");
            }



        }

        static string GetDeviceID(int deviceNum)
        {
            string devId = $"RIoT_Test_{deviceNum}";
            return devId;

        }



    }
}
