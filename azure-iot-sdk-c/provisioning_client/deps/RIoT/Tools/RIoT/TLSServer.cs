
namespace RIoT
{

    using System;
    using System.Diagnostics;
    using System.Threading;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography;
    using System.Text;

    using Security.Cryptography;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Math.EC;
    using System.Collections.Generic;

    public sealed class SslTcpServer
    {
        static X509Certificate2 ServerCert;
        static X509Certificate2 DeviceCA;
        static string DeviceIDPEMFile;
        //static internal int TargetFirmwareVersionNumber;

        internal static void RunServer(string _serverCA, string serverCert, string serverKey, string deviceCA, string deviceIDPublic)
        {
            if (deviceCA != null) DeviceCA = new X509Certificate2(deviceCA);
            DeviceIDPEMFile = deviceIDPublic;

            // Windows likes PFX files so make one out of the cert and key PEM files
            string serverPFXFile = "TO_ServerKey.pfx";
            string password = "passw0rd";
            Helpers.MakePFXFile(serverCert, serverKey, serverPFXFile, password);

            ServerCert = new X509Certificate2(serverPFXFile, password);
            TcpListener listener = new TcpListener(IPAddress.Any, 5556);
            Helpers.Notify("SSL Server starting on localhost:5556");
            listener.Start();
            while (true)
            {
                Helpers.Notify("Waiting for a client to connect...");
                TcpClient client = listener.AcceptTcpClient();
                if (deviceIDPublic != null)
                {
                    ProcessClient(client, false);
                    return;
                }
                else
                {
                    ProcessClient(client, true);
                    // and wait for the next one
                }
            }

        }
        private static void ProcessClient(TcpClient client, bool chat)
        {
            SslStream sslStream = new SslStream(client.GetStream(), false, ValidateDeviceCertificate);
            try
            {
                // authenticate as server and request client cert.  This invokes the ValidateDeviceCertificate
                // callback.  If the callback returns false (or there are other errors), AuthenticateAsServer
                // throws an exception
                sslStream.AuthenticateAsServer(ServerCert, true, SslProtocols.Tls, false);
                // if we get to here, all TLS+RIoT checks have succeeded.
                // Print info about the connected device
                var deviceCert = sslStream.RemoteCertificate;
                var devCert2 = new X509Certificate2(deviceCert);
                var info = ExtensionDecoder.Decode(devCert2);
                if (info == null)
                {
                    // should not happen since the cert has already been 
                    // validated in the callback..
                    Helpers.Notify("Unexpected missing or malformed RIoT device certificate", true);
                    return;
                }
                // we have a good device: tell the world
                Helpers.Notify($"RIoT Device Connected:");
                Helpers.Notify($"            DeviceID:{Helpers.Hexify(info.EncodedDeviceIDKey).Substring(0, 60) + "..."}");
                Helpers.Notify($"                FWID:{Helpers.Hexify(info.FirmwareID)}");

                if (chat)
                {
                    // Read a message from the client.
                    sslStream.ReadTimeout = 10000;
                    sslStream.WriteTimeout = 10000;
                    Helpers.Notify("Waiting for client message...");
                    if (DeviceIDPEMFile != null)
                    {
                        string messageData = ReadMessageX(sslStream);
                        Helpers.Notify($"Server received: {messageData}");
                        // Write a message to the client.
                        byte[] message = Encoding.UTF8.GetBytes("Hello from the server.<EOF>");
                        Helpers.Notify("Sending hello message.");
                        sslStream.Write(message);
                    }
                    else
                    {
                        ProcessFakeDRSMessage(sslStream);
                    }
                }
                // give the client some time to process before closing the stream
                Thread.Sleep(30);
            }
            catch (AuthenticationException e)
            {
                Helpers.Notify($"Exception in AuthenticateAs server block: {e.Message}", true);
                if (e.InnerException != null)
                {
                    Helpers.Notify($"Inner exception: {e.InnerException.Message}", true);
                }
                Helpers.Notify("Authentication failed - closing the connection.", true);
                sslStream.Close();
                client.Close();
                return;
            }
            finally
            {
                Helpers.Notify("Client has disconnected. Stream is closing");
                sslStream.Close();
                client.Close();
            }
        }

        private static string ReadMessageX(SslStream sslStream)
        {
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }


        /// <summary>
        /// This callback validates a RIoT certificate chain or a bare Alias certificate.
        /// We generally don't want to validate a chain against the user or machine cert store, 
        /// so we do it (semi) manually with X509Chain.  If the device only presents the Alias 
        /// Certificate (no chain) we call it a "bare certificate.)
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="_certificate"></param>
        /// <param name="inChain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        public static bool ValidateDeviceCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate _certificate, X509Chain inChain,
            SslPolicyErrors sslPolicyErrors)
        {

            //ValidateBareCertificateWithBcrypt(new X509Certificate2(_certificate));


            if (_certificate==null)
            {
                // not sure that this can happen
                Helpers.Notify($"No certificate presented by client", true);
                return false;
            }

            // This is the leaf (alias) certificate
            X509Certificate2 certificate = new X509Certificate2(_certificate);

            // Did the device just send one certificate?  If so, we don't check the chain: we just
            // check that the certificate was signed by a known DeviceID in the routine below.
            // Note that if the built-in chain builder found certificates in the system store to build 
            // chain, then inChain will contain those and the processing will follow the "chain" rules
            // rather than the bare-certificate validation rules.
            if (inChain.ChainElements.Count==1)
            {
                Helpers.Notify($"count==1", true);
                return ValidateBareCertificate(certificate);
            }

            // Else we have a chain...
            // We need at least 3 certificates:
            //      Alias
            //      DeviceID (issued by vendor)
            //      [zero or any number of intermediate CA]
            //      Device Vendor CA

            int chainLength = inChain.ChainElements.Count;
            if (chainLength < 3)
            {
                Helpers.Notify($"Chain length too short: {chainLength}", true);
                return false;
            }
            Helpers.Notify($"Device presented a certificate chain of length {inChain.ChainElements.Count}");

            // Put the device-provided chain in a new X509Chain so that we can validate it
            X509Chain chain = new X509Chain(false);

            // todo: this seems like a reasonable starting point for the flags
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Note: this flag seems to be ignored.  In any case, we don't use the 
            // machine or user-context cert store: we check the root against DeviceCA
            // provided as a parameter during class instantiation (or a database of authorized
            // CAs in the final service.)
            chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;

            // Add the intermediate and root-CA certs that came out of the TLS session.
            foreach (var c in inChain.ChainElements)
            {
                chain.ChainPolicy.ExtraStore.Add(c.Certificate);
            }

            // Can we build a chain using the leaf-cert and the rest of the provided certs?
            bool valid = chain.Build(new X509Certificate2(certificate));
            if (!valid)
            {
                Helpers.Notify($"Chain building failed: {chainLength}", true);
                foreach (var err in chain.ChainStatus)
                {
                    
                    Helpers.Notify($"        Error:{err.StatusInformation.ToString()}", true);
                }
                return false;
            }
            // Get the chain we built.  Regardless of what the client sent, we
            // want a chain of 3 or more certificates (alias, DevID, [...], CA) in our 
            // chain.
            var deviceCertChain = chain.ChainElements;
            if (deviceCertChain.Count < 3)
            {
                Helpers.Notify($"Chain length too short: {deviceCertChain.Count}", true);
                return false;
            }

            // Is the root one of the registered CAs for this DRS instance?
            // Here we just recognize a single root
            var thisDeviceRootCert = deviceCertChain[deviceCertChain.Count - 1];
            if (thisDeviceRootCert.Certificate.Thumbprint != DeviceCA.Thumbprint)
            {
                Helpers.Notify($"Device not certified by a known/authorized CA", true);
                return false;
            }

            // Next, extract the RIoT extension, and see if it is present/well-formed 
            var aliasCert = deviceCertChain[0].Certificate;
            var deviceIDCert = deviceCertChain[1].Certificate;

            var deviceInfo = ExtensionDecoder.Decode(aliasCert);
            // check we have a good extension
            if (deviceInfo == null)
            {
                Helpers.Notify("Certificate does not have well-formed RIoT extension", true);
                return false;
            }
            // Check that the DevID claimed in the RIoT extension matches that defined by the
            // cert chain.  This is a *critical* security check if the server just wants to authenticate
            // based on the Alias (leaf) certificate rather than the DeviceID cert and the Alias Cert.
            var encodedDeviceID = deviceIDCert.PublicKey.EncodedKeyValue;
            if (!Helpers.ArraysAreEqual(encodedDeviceID.RawData, deviceInfo.EncodedDeviceIDKey))
            {
                Helpers.Notify("Alias Certificate DeviceID does not match DeviceID certificate", true);
                return false;
            }
            Helpers.Notify("All RIoT Certificate checks passed");
            return true;

        }

        /// <summary>
        /// If the device is not "vendor certified" it will only present the Alias Certificate, which is
        /// validated in this routine.  The essential security checks are:
        ///     1) Does it have a RIoT extension containing the DeviceID?
        ///     2) Is the certificate signed by the corresponding private DeviceID?
        ///     3) Is the DeviceID "authorized."  In the simple case, is it exactly the device DeviceID
        ///             indicated by the code that instantiated the TLSServer object.
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        internal static bool ValidateBareCertificate(X509Certificate2 certificate)
        {
            Helpers.Notify($"Device presented a bare certificate");

            var deviceInfo = ExtensionDecoder.Decode(certificate);
            // check we have a good extension
            if (deviceInfo == null)
            {
                Helpers.Notify("Certificate does not have well-formed RIoT extension", true);
                return false;
            }
            var devIdPubKeyDEREncoded = deviceInfo.EncodedDeviceIDKey;
            if (devIdPubKeyDEREncoded.Length != 65)
            {
                Helpers.Notify("Public key in extension has incorrect length", true);
                return false;
            }

            // validating the certificate is signed with the public key encoded in the extension.
            // This is a critical security check.
            // Note: this uses the Bouncy Castle libraries
            var bcCert = new X509CertificateParser().ReadCertificate(certificate.GetRawCertData());
            X9ECParameters p = NistNamedCurves.GetByName("P-256");
            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
            var pt = parameters.Curve.DecodePoint(deviceInfo.EncodedDeviceIDKey);
            ECPublicKeyParameters bcPubKey = new ECPublicKeyParameters(pt, parameters);
            try
            {
                bcCert.Verify(bcPubKey);
            }
            catch(Exception e)
            {
                Helpers.Notify($"Certificate is not signed using key in extension {e.ToString()}", true);
                return false;
            }
            if (DeviceIDPEMFile != null)
            {
                // Is this key one of the keys registered with DRS (this test code only has one.)
                ECPublicKeyParameters authorizedDevice = (ECPublicKeyParameters)Helpers.ReadPemObject(DeviceIDPEMFile);
                // todo: there are probably better equality tests than this!
                bool keyIsRecognized =
                    (authorizedDevice.Q.XCoord.ToString() == bcPubKey.Q.XCoord.ToString()) &&
                    (authorizedDevice.Q.YCoord.ToString() == bcPubKey.Q.YCoord.ToString());

                if (!keyIsRecognized)
                {
                    Helpers.Notify($"DeviceID is not known", true);
                    return false;
                }
                return true;
            }
            // this code supports the "FakeDRSServer.  Here, any device that connects to us is presumed good

            return true;
        }

        internal static bool ValidateBareCertificateWithBcrypt(X509Certificate2 certificate)
        {
            var deviceInfo = ExtensionDecoder.Decode(certificate);
            // check we have a good extension
            if (deviceInfo == null)
            {
                Helpers.Notify("Certificate does not have well-formed RIoT extension", true);
                return false;
            }
            var devIdPubKeyDEREncoded = deviceInfo.EncodedDeviceIDKey;
            if(devIdPubKeyDEREncoded.Length!=65)
            {
                Helpers.Notify("Public key in extension has incorrect length", true);
                return false;
            }

            // We need to convert to the Windows key format before we can import
            // #define BCRYPT_ECDSA_PUBLIC_P256_MAGIC  0x31534345  // ECS1
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375520(v=vs.85).aspx
            byte[] windowsEncodedKey = new byte[32 * 2 + 4 + 4];
            // todo - endianess
            byte[] magic = BitConverter.GetBytes((uint)0x31534345);
            byte[] len = BitConverter.GetBytes((uint)32);

            Array.Copy(magic, 0, windowsEncodedKey, 0, 4);
            Array.Copy(len, 0, windowsEncodedKey, 4, 4);
            Array.Copy(devIdPubKeyDEREncoded, 1, windowsEncodedKey, 8, 32);
            Array.Copy(devIdPubKeyDEREncoded, 32+1, windowsEncodedKey, 8+32, 32);

            var devIdPubKey = CngKey.Import(windowsEncodedKey, CngKeyBlobFormat.EccPublicBlob);

            ECDsaCng verifier = new ECDsaCng(devIdPubKey);

            ECDsaCng testSigner = new ECDsaCng(256);
            var sig = testSigner.SignData(new byte[] { 1, 2, 3, 4 });
            bool okx = testSigner.VerifyData(new byte[] { 1, 2, 3, 4 }, sig);

            var bits = ExtensionDecoder.Decompose(certificate);
            var tbsHash = Helpers.HashData(bits.Tbs,0,  bits.Tbs.Length);
            bool ok = verifier.VerifyHash(tbsHash, bits.Signature);


            return true;

        }

        static Object HubLock = new object();
        static void ProcessFakeDRSMessage(SslStream s)
        {
            lock (HubLock)
            {
                try
                {
                    // clients send us their Id
                    string messageFromClient = ReadMessage(s);

                    X509Certificate2 cert = new X509Certificate2(s.RemoteCertificate);
                    UpdateDemo.HubController.FakeDRSServerEnrollOrRefreshDevice(messageFromClient, cert.Thumbprint);
                    Debug.Write($"Device {messageFromClient} connected");
                    
                    SendMessage(s, "OK");
                    Thread.Sleep(30);
                }
                catch(Exception e)
                {
                    Helpers.Notify($"ProcessFakeDRSMessage error {e.ToString()}");

                }

            }


        }

        internal static void SendMessage(SslStream sslStream, string _message)
        {
            if (_message.Length > 256) throw new ArgumentException("too long");
            byte[] message = Encoding.UTF8.GetBytes(_message);
            try
            {
                byte[] len = new byte[] { (byte)message.Length };
                sslStream.Write(len, 0, 1);
                sslStream.Write(message, 0, message.Length);
                sslStream.Flush();
            } catch(Exception e)
            {
                Debug.WriteLine("error writing: " + e.ToString());
                throw;
            }
        }


        internal static string ReadMessage(SslStream sslStream)
        {
            byte[] buf = new byte[1024];
            try
            {
                int numRead = sslStream.Read(buf, 0, 1);
                if (numRead != 1)
                {
                    Helpers.Notify("Got a bad message from the server");
                }
                int pos = 0;
                int lenX = (int)buf[0];
                while (true)
                {
                    numRead = sslStream.Read(buf, pos, lenX - pos);
                    pos += numRead;
                    if (pos == lenX) break;
                }
                string serverMessage = Encoding.UTF8.GetString(buf, 0, lenX);
                return serverMessage;
            }
            catch (Exception e)
            {
                Debug.WriteLine("error reading: " + e.ToString());
                throw;
            }
        }

        public static void ValidateEmulatorChain(string alias, string deviceID, string root)
        {
            try
            {
                X509Certificate2 aliasCert = new X509Certificate2();
                X509Certificate2 devIDCert = null;
                X509Certificate2 rootCert = new X509Certificate2();

                rootCert.Import(Helpers.GetBytesFromPEM(root, "CERTIFICATE"));

                aliasCert = new X509Certificate2(Helpers.GetBytesFromPEM(alias, "CERTIFICATE"));
                devIDCert = new X509Certificate2(Helpers.GetBytesFromPEM(deviceID, "CERTIFICATE"));
                rootCert = new X509Certificate2(Helpers.GetBytesFromPEM(root, "CERTIFICATE"));

                var chain = new X509Chain
                {
                    ChainPolicy =
                    {
                        RevocationMode = X509RevocationMode.NoCheck,
                        RevocationFlag = X509RevocationFlag.ExcludeRoot,
                        VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
                    }
                };

                //chain.ChainPolicy.ExtraStore.Add(devIDCert);
                chain.ChainPolicy.ExtraStore.Add(rootCert);

                bool chainBuildSucceeded = chain.Build(aliasCert as X509Certificate2 ?? new X509Certificate2(aliasCert.Export(X509ContentType.Cert)));

                if (!chainBuildSucceeded)
                {
                    foreach (var err in chain.ChainStatus)
                    {
                        Helpers.Notify($"Error:{err.StatusInformation.ToString()}", true);
                    }
                }

            }
            catch (Exception e)
            {
                Helpers.Notify($"ValidateEmulatorChain error {e.ToString()}");
            }
        }

    }



}
