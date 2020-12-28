using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DiceRiotEmulator;

namespace drtester
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] uds = new byte[32];
            byte[] fwid = new byte[32];
            fwid[0] = 1;

            var bundle = DiceRiotEmulator.RIoTEngine.CreateDeviceAuthBundle(uds, fwid);

            string challengePoPCN = "CN=XXXXyyyyZZZZ";
            var popCertPem = DiceRiotEmulator.RIoTEngine.CreateDevIDPoP(bundle, challengePoPCN);

            File.WriteAllText("AliasCert.PEM", bundle.AliasCredential.CertPem);
            File.WriteAllText("DeviceIDCert.PEM", bundle.DeviceIDCredential.CertPem);
            File.WriteAllText("DeviceIDSelfSignedCert.PEM", bundle.SelfSignedDeviceIDCredential.CertPem);
            File.WriteAllText("RootCert.PEM", bundle.RootCredential.CertPem);
            File.WriteAllText("DevIDCSR.PEM", bundle.Csr.CsrPem);

            File.WriteAllBytes("AliasCert.CER", bundle.AliasCredential.Cert.GetEncoded());
            File.WriteAllBytes("DeviceIDCert.CER", bundle.DeviceIDCredential.Cert.GetEncoded());
            File.WriteAllBytes("DeviceIDSelfSignedCert.CER", bundle.SelfSignedDeviceIDCredential.Cert.GetEncoded());
            File.WriteAllBytes("RootCert.CER", bundle.RootCredential.Cert.GetEncoded());
            File.WriteAllText("DevIDPopCert.PEM", popCertPem);

            string helpString =
                "Certificate and chain validation:\n" +
                "Vendor chain:     openssl verify -verbose -purpose sslclient -show_chain -trusted rootCert.PEM -untrusted DeviceIDCert.PEM AliasCert.PEM\n" +
                "Self signed:      openssl verify -verbose -purpose sslclient -show_chain -trusted DeviceIDSelfSignedCert.PEM  AliasCert.PEM\n" +
                "CSR:              openssl req -text -in DevIDCSR.PEM\n" +
                "dump:             openssl x509 -text -in AliasCert.pem\n";

            Console.WriteLine(helpString);
            Debug.WriteLine(helpString);

            Thread.Sleep(3000);

            return;
        }
    }
}
