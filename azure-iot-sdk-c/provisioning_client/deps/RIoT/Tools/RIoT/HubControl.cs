using System;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.Devices;
using Microsoft.Azure.Devices.Client.Exceptions;
using Microsoft.Azure.Devices.Shared;

namespace RIoT
{
    /// <summary>
    /// 
    /// </summary>
    class HubControl
    {
        string ConnectionStringFile = "c:\\tmp\\ConnectionString.txt";
        string ControlDevice = "ControlDevice";
        byte[] ControlDeviceKey = Helpers.HashData(new byte[] { 0 }, 0, 1);


        RegistryManager RegMgr;
        internal HubControl()
        {
        }
        /// <summary>
        /// Make an administrative connection to the hub
        /// </summary>
        /// <returns></returns>
        internal bool Connect()
        {
            if (!File.Exists(ConnectionStringFile))
            {
                Helpers.Notify($"Missing connection string file {ConnectionStringFile}.  This file is omitted from the distribution because it contains passwords.", true);
                Helpers.Notify($"The file should contain somehting like this:", true);
                Helpers.Notify($"HostName=pengland.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=0frrKXXXSomeStuffXXXXvWQ=", true);
                return false;
            }
            var connectionString = File.ReadAllText(ConnectionStringFile);
            try
            {
                RegMgr = RegistryManager.CreateFromConnectionString(connectionString);
            }
            catch (Exception e)
            {
                Helpers.Notify($"Failed to CreateFromConnectionString: {e.ToString()}");
                return false;
            }
            return true;
        }
        /// <summary>
        /// List the current devices
        /// </summary>
        /// <param name="numDevices"></param>
        /// <returns></returns>
        internal List<string> GetDeviceIDs(int numDevices = 100)
        {
            var deviceIds = new List<string>();
            var x = RegMgr.GetDevicesAsync(100);
            foreach (var d in x.Result)
            {
                Debug.WriteLine($"{d.ETag} -- {d.Id}");
                deviceIds.Add(d.Id);
            }
            return deviceIds;
        }

        /// <summary>
        /// Enroll a new device
        /// </summary>
        /// <param name="deviceId"></param>
        /// <param name="fwVersionNumber"></param>
        /// <param name="fwId"></param>
        /// <param name="aliasCertThumbprint"></param>
        /// <returns></returns>
        internal Device EnrollDevice(string deviceId, int fwVersionNumber, string fwId, string aliasCertThumbprint)
        {
            if (GetDeviceIDs().Contains(deviceId))
            {
                Helpers.Notify($"Device {deviceId} already exists");
                return null;
            }
            Device newDevice = null;
            Device dTemplate = new Device(deviceId);
            dTemplate.Authentication = new AuthenticationMechanism();
            dTemplate.Authentication.X509Thumbprint = new X509Thumbprint();
            dTemplate.Authentication.X509Thumbprint.PrimaryThumbprint = aliasCertThumbprint;
            try
            {
                // create the device
                newDevice = RegMgr.AddDeviceAsync(dTemplate).Result;
                // and set the FWID property in the twin 
                var props = new TwinCollection();
                props["FWID"] = fwId;
                props["VersionNumber"] = fwVersionNumber.ToString();

                var twin = RegMgr.GetTwinAsync(deviceId).Result;
                twin.Properties.Desired = props;
                RegMgr.UpdateTwinAsync(deviceId, twin, twin.ETag).Wait();

                return newDevice;
            }
            catch (Exception e)
            {
                Helpers.Notify($"Failed to add device. Error is {e.ToString()}");
                return null;
            }
        }

        internal bool RefreshDevice(string deviceId, int fwVersionNumber, string fwid, string aliasCertThumbprint, bool primaryNotSecondary)
        {
            var dev = RegMgr.GetDeviceAsync(deviceId).Result;
            if (primaryNotSecondary)
            {
                dev.Authentication.X509Thumbprint.PrimaryThumbprint = aliasCertThumbprint;
            }
            else
            {
                dev.Authentication.X509Thumbprint.SecondaryThumbprint = aliasCertThumbprint;
            }
            RegMgr.UpdateDeviceAsync(dev).Wait();

            var twin = RegMgr.GetTwinAsync(deviceId).Result;
            twin.Properties.Desired["FWID"] = fwid;
            twin.Properties.Desired["VersionNumber"] = fwVersionNumber.ToString();
            RegMgr.UpdateTwinAsync(deviceId, twin, twin.ETag).Wait();

            return true;
        }

        internal int GetTargetVersionNumber()
        {
            try
            {
                /*
                /////////////////////////////////////////////////
                    Look at Notes.txt for what's going on'
                /////////////////////////////////////////////////
                */
                var twin = RegMgr.GetTwinAsync(ControlDevice).Result;
                int targetVersionNumber = (int)twin.Properties.Desired["VersionNumber"];
                return targetVersionNumber;
            }
            catch (Exception ex)
            {
                Helpers.Notify($"Failed to get control device twin. Error is {ex.ToString()}");
                return 0;
            }

        }


        internal bool RemoveDevice(string devId)
        {
            // quick try to see if it exists
            if(!GetDeviceIDs().Contains(devId))
            {
                // nothing to do.  
                return false;
            }
            // else try to delete 
            try
            {
                RegMgr.RemoveDeviceAsync(devId);

            }
            catch (Exception e)
            {
                Helpers.Notify($"Failed to remove device. Error is {e.ToString()}");
                return false;
            }
            return true;
        }
        internal bool RemoveAllDevices()
        {
            var devIds = GetDeviceIDs();
            foreach(var devId in devIds)
            {
                Device dd = RegMgr.GetDeviceAsync(devId).Result;
                RegMgr.RemoveDeviceAsync(dd);
            }
            return true;
        }

        internal bool FakeDRSServerEnrollOrRefreshDevice(string deviceId, string certThumbprint)
        {
            if(!GetDeviceIDs().Contains(deviceId))
            {
                // make a ndw device
                EnrollDevice(deviceId, 0, "", certThumbprint);
                return true;
            }
            // else refresh
            var dev = RegMgr.GetDeviceAsync(deviceId).Result;

            dev.Authentication.X509Thumbprint.PrimaryThumbprint = certThumbprint;
            RegMgr.UpdateDeviceAsync(dev).Wait();

            // todo check the attestation is good

            return true;
        }
    }
}
