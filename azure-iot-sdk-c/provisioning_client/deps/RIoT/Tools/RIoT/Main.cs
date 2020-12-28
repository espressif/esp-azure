using System;
using System.Threading;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RIoT
{
    // Useful utility 
    //                        http://www.lapo.it/asn1js/

    class Program
    {
        // The RIoT utility expects to find all keys and certs in IODir (which can be changed 
        // through the command line.)  File names are as listed  below, and are not configurable
        internal static string IODir = "./Certs/";
        // device certs and keys
        internal static string AliasCert = "AliasCert.PEM";
        internal static string AliasKey = "AliasKey.PEM";
        internal static string DeviceCertChain = "DeviceCertChain.PEM";
        internal static string DeviceCertChainIncAlias = "DeviceCertChainIncAlias.PEM";
        internal static string DeviceCA = "DeviceCA.PEM";
        internal static string DeviceIDPublic = "DeviceIDPublic.PEM";
        internal static string DeviceIDPrivate = "DeviceIDPrivate.PEM"; // just for the update demo
        internal static string DeviceIDCSR = "DeviceIDCSR.PEM";
        // cert+key file that is generated
        internal static string AliasCertPFX = "AliasCert.PFX";

        // server certs and keys
        internal static string ServerCA = "ServerCA.PEM";
        internal static string ServerChain = "ServerChain.PEM";
        internal static string ServerCert = "ServerCert.PEM";
        internal static string ServerKey = "ServerKey.PEM";

        // For IoT hub testing
        internal static string IotHubUri = "pengland.azure-devices.net";

        // to test a bunch of different devices simultaneously
        static int DeviceNumber = -1;


        // ossl command lines (client and server) need a CA file with both client and 
        // server roots
        internal static string DeviceCertChainAndServerCA = "DeviceCertChainAndServerCA.PEM";

        // modifies the behavior of -e2e
        internal static bool MakeCerts = true;

        // This is from the MS/MSR arc.  
        //internal static string DeviceIdOid = "1.3.6.1.4.1.311.89.3.1";
        internal static string DeviceIdOid = "2.23.133.5.4.1";

        static List<CommandLineOption> Parms = new List<CommandLineOption>();
        internal static string ChainOrBareCert = "C";
        static List<CommandLineOption> ActiveParms = new List<CommandLineOption>();

        static void Main(string[] args)
        {

            // This invokes testing using WeClient, etc.  Not yet working.
            //HttpsListener.StartListener(IODir + ServerCert, IODir + ServerKey, IODir + ServerCA, IODir+AliasCert, IODir+AliasKey);

            InitParms();
            bool ok = ParseParms(args);
            if (!ok) return;

            string workingDir = Environment.CurrentDirectory;

            foreach(var action in ActiveParms)
            {
                if (action.Flag == "dir")
                {
                    IODir = action.Parameter;
                    if (!IODir.EndsWith("\\")) IODir += "\\";
                    continue;
                }

                if (action.Flag == "gentest")
                {
                    CertMaker m = new CertMaker(IODir);
                    m.MakeNew(5, false, 0);
                    continue;
                }

                if (action.Flag == "bare")
                {
                    ChainOrBareCert = "B";
                    continue;
                }

                if (action.Flag == "certify")
                {
                    CertMaker m = new CertMaker(IODir);
                    m.CertifyExisting(5);
                    continue;
                }

                if (action.Flag == "certifyj")
                {
                    CertMaker m = new CertMaker(IODir);
                    m.CertifyExistingForJava(5);
                    continue;
                }
                if (action.Flag == "csr")
                {
                    CertMaker m = new CertMaker(IODir);
                    m.CertifyExistingFromCsr(5);
                    continue;
                }

                if (action.Flag == "server")
                {
                    SslTcpServer.RunServer(
                        ToPath(Program.ServerCA),
                        ToPath(Program.ServerCert),
                        ToPath(Program.ServerKey),
                        ToPath(Program.DeviceCA),
                        ToPath(Program.DeviceIDPublic)
                        );
                    continue;
                }

                if (action.Flag == "testemu")
                {
                    SslTcpServer.ValidateEmulatorChain(@"AliasCert.pem", @"DeviceIDCrt.pem", @"r00tcrt.pem");
                    continue;
                }

                if (action.Flag == "sc")
                {
                    Helpers.Notify("Starting TLSClient...");
                    var psi = new ProcessStartInfo("TlsClient.exe");
                    psi.Arguments = ChainOrBareCert + " " + IODir;
                    psi.UseShellExecute = true;
                    var proc = Process.Start(psi); ;

                    SslTcpServer.RunServer(
                        ToPath(Program.ServerCA),
                        ToPath(Program.ServerCert),
                        ToPath(Program.ServerKey),
                        ToPath(Program.DeviceCA),
                        ToPath(Program.DeviceIDPublic)
                        );
                    proc.WaitForExit();
                    continue;
                }

                if (action.Flag == "nogen")
                {
                    MakeCerts = false;
                    continue;
                }

                if (action.Flag == "e2e")
                {
                    if (MakeCerts)
                    {
                        Helpers.Notify("Making a new certificate set");
                        CertMaker m = new CertMaker(IODir);
                        m.MakeNew(5, false, 0);
                        //m.MakeNew(5, true, 1);
                    }

                    Helpers.Notify("Starting TLSClient...");
                    var psi = new ProcessStartInfo("TlsClient.exe");
                    psi.Arguments = ChainOrBareCert + " " + IODir;
                    psi.UseShellExecute = true;
                    var proc = Process.Start(psi); ;

                    SslTcpServer.RunServer(
                        ToPath(Program.ServerCA),
                        ToPath(Program.ServerCert),
                        ToPath(Program.ServerKey),
                        ToPath(Program.DeviceCA),
                        ToPath(Program.DeviceIDPublic)
                        );
                    proc.WaitForExit();
                    continue;
                }

                if (action.Flag == "ossl_server")
                {
                    Helpers.Notify("OpenSSL s_server parameters for TLS test server (start in directory with certificates and files)");
                    Helpers.Notify($"openssl s_server -cert {ToPath(ServerCert)} -key {ToPath(ServerKey)} -CAfile {ToPath(DeviceCertChainAndServerCA)} -status_verbose -verify 10 -rev -accept 5556");
                    continue;
                }
                if (action.Flag == "ossl_client")
                {
                    Helpers.Notify("OpenSSL s_client parameters for TLS test client (start in directory with certificates and files)");
                    Helpers.Notify($"openssl s_client -connect localhost:5556 -cert {ToPath(AliasCert)} -key {ToPath(AliasKey)} -CAfile {ToPath(DeviceCertChainAndServerCA)}");
                    continue;
                }
                if (action.Flag == "tls_client")
                {
                    Helpers.Notify("Starting TLSClient...");
                    var psi = new ProcessStartInfo("TlsClient.exe");
                    psi.Arguments = ChainOrBareCert + " " + IODir;
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    psi.RedirectStandardError = true;
                    var proc = Process.Start(psi); ;
                    string op = proc.StandardError.ReadToEnd();
                    proc.WaitForExit();
                    Helpers.Notify(op);
                    continue;
                }

                if(action.Flag == "demo")
                {
                    var demo = new UpdateDemo();
                    demo.FakeDRSTest();
                }


            }

            if(System.Diagnostics.Debugger.IsAttached)
            {
                Thread.Sleep(3000);
            }

            return;
        }
        static void InitParms()
        {
            Parms.Add(new CommandLineOption("help", "Print this text"));
            Parms.Add(new CommandLineOption("gentest", "Make a set of client and server test certificates"));
            Parms.Add(new CommandLineOption("certify", "Certify a device given a bare DeviceIDPublic.PEM file"));
            Parms.Add(new CommandLineOption("certifyj", "Certify a device for Java"));
            Parms.Add(new CommandLineOption("csr", "Make certs given a DeviceIDCsr.PEM (AliasKey and AliasCert are assumed to exist)"));
            Parms.Add(new CommandLineOption("server", "Start a TLS test server using SSLStream"));
            Parms.Add(new CommandLineOption("server2", "Start a TLS test server using "));
            Parms.Add(new CommandLineOption("sc", "Start a TLS test server AND launch TlsClient.exe"));
            Parms.Add(new CommandLineOption("nogen", "Modifies -e2e to skip creation of a new key and cert set"));
            Parms.Add(new CommandLineOption("e2e", "Make a new set of test certs, start a TLS test server, and launch TlsClient.exe"));
            Parms.Add(new CommandLineOption("ossl_client", "Print command line parameters for an openssl test client"));
            Parms.Add(new CommandLineOption("ossl_server", "Print command line parameters for an openssl test server"));
            Parms.Add(new CommandLineOption("tls_client", "Start the TlsClient test program and wait for it to complete"));
            Parms.Add(new CommandLineOption("dir", "Set the directory to put and gets certs and keys", 1));
            Parms.Add(new CommandLineOption("bare", "Present a bare alias certificate rather than a chain (use before other options)"));
            Parms.Add(new CommandLineOption("demo", "Update demo"));
            Parms.Add(new CommandLineOption("testemu", "Test cert chain from emulator"));
        }
        static bool ParseParms(string[] parms)
        {
            if(parms.Length==0)
            {
                parms = new string[] { "help" };
            }

            int j = 0;
            while (true)
            {
                if (j == parms.Length) break;
                var parm = parms[j++];
                var parmL = parm.ToLower();
                bool processed = false;
                foreach (var p in Parms)
                {
                    if ("-" + p.Flag == parmL)
                    {
                        p.Active = true;
                        if (p.NumParms != 0)
                        {
                            if (j == parms.Length - 1)
                            {
                                Helpers.Notify($"Missing paramter for flag: {p.Flag}", true);
                                return false;
                            }
                            p.Parameter = parms[j++];
                        }
                        ActiveParms.Add(p);
                        processed = true;
                        continue;
                    }
                }
                if(!processed)
                {
                    Helpers.Notify($"Unknown command line parameter: {parm}", true);
                    Help();
                    return false;
                }
            }
            return true;
        }
        internal static string ToPath(string fileName)
        {   if (DeviceNumber < 0)
            {
                return IODir + fileName;
            }
            else
            {
                // hacky way of supporting lots of devices
                return IODir + $"_{DeviceNumber}_" + fileName;
            }
        }
        internal static void SetDeviceNumber(int deviceNum)
        {
            DeviceNumber = deviceNum;

        }



        static void Help()
        {
            var progName = Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName);
            Helpers.Notify($"Usage:\n{progName} options");
            foreach (var p in Parms)
            {
                var px = p.NumParms == 0 ? "" : "[string parm]";
                Helpers.Notify($"     -{p.Flag} {px}            {p.Help}");
            }
        }


    }
    internal class CommandLineOption
    {
        internal string Flag;
        internal int NumParms;
        internal string Help;

        internal bool Active = false;
        internal string Parameter;

        internal CommandLineOption(string _flag, string _help, int _numParms=0)
        {
            Flag = _flag;
            Help = _help;
            NumParms = _numParms;
        }

    }

}
