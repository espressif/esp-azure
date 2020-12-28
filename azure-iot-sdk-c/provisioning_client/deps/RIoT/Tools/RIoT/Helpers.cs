
namespace RIoT
{
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Utilities.Encoders;
    using Org.BouncyCastle.X509;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    public class Helpers
    {
        /// <summary>
        /// Make a copy of a byte array
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        public static byte[] CopyArray(byte[] x)
        {
            var d = new byte[x.Length];
            Array.Copy(x, d, x.Length);
            return d;
        }

        /// <summary>
        /// Copy of part of a byte array
        /// </summary>
        /// <param name="x"></param>
        /// <param name="startPos"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        public static byte[] CopyArray(byte[] x, int startPos, int len)
        {
            var d = new byte[len];
            Array.Copy(x, startPos, d, 0, len);
            return d;
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
        /// byte-array equality check
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        internal static bool ArraysAreEqual(byte[] x, byte[] y) => Enumerable.SequenceEqual(x, x);

        internal static byte[] GetRepeating(int b, int count)
        {
            byte[] r = new byte[count];
            for (int j = 0; j < count; j++) r[j] = (byte)b;
            return r;
        }

        /// <summary>
        /// Windows TLS needs the Alias public + private key in a PFX file
        /// </summary>
        /// <param name="certFile"></param>
        /// <param name="keyFile"></param>
        internal static void MakePFXFile(string certFile, string keyFile, string outputPfxFile, string password)
        {
            CryptoApiRandomGenerator rg = new CryptoApiRandomGenerator();
            var rng = new SecureRandom(rg);
            // get the cert
            var parser = new X509CertificateParser();
            var cert = parser.ReadCertificate(File.ReadAllBytes(certFile));
            // get the key
            Org.BouncyCastle.OpenSsl.PemReader pemReader =
            new Org.BouncyCastle.OpenSsl.PemReader(new StringReader(File.ReadAllText(keyFile)));
            AsymmetricCipherKeyPair kp = pemReader.ReadObject() as AsymmetricCipherKeyPair;


            // Put the key and cert in an PKCS12 store so that the WIndows TLS stack can use it
            var store = new Pkcs12Store();
            string friendlyName = cert.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(cert);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(kp.Private), new[] { certificateEntry });

            var stream = new MemoryStream();
            var pwd = password == null ? null : password.ToCharArray();
            store.Save(stream, pwd, rng);
            File.WriteAllBytes(outputPfxFile, stream.ToArray());
            return;
        }

        internal static void Notify(string message, bool isError = false)
        {
            if (isError)
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            Debug.WriteLine(message);
            Console.WriteLine(message);
            Console.ResetColor();
            return;
        }

        internal static void WritePEMObjects(string fileName, Object[] pemObjects)
        {
            var stream = new StreamWriter(fileName, false);
            Org.BouncyCastle.OpenSsl.PemWriter writer = new Org.BouncyCastle.OpenSsl.PemWriter(stream);
            foreach (var o in pemObjects)
            {
                writer.WriteObject(o);
            }

            writer.Writer.Flush();
            stream.Close();
        }

        internal static void WritePEMObject(string fileName, Object pemObject)
        {
            var stream = new StreamWriter(fileName, false);
            Org.BouncyCastle.OpenSsl.PemWriter writer = new Org.BouncyCastle.OpenSsl.PemWriter(stream);
            writer.WriteObject(pemObject);
            writer.Writer.Flush();
            stream.Close();
        }

        internal static Object ReadPemObject(string fileName)
        {
            var stream = new StreamReader(fileName);
            Org.BouncyCastle.OpenSsl.PemReader reader = new Org.BouncyCastle.OpenSsl.PemReader(stream);
            var o = reader.ReadObject();
            stream.Close();
            return o;
        }

        internal static byte[] GetBytesFromPEM(string pemFile, string section)
        {
            var pem = File.ReadAllText(pemFile);
            var header = String.Format("-----BEGIN {0}-----", section);
            var footer = String.Format("-----END {0}-----", section);

            var start = pem.IndexOf(header, StringComparison.Ordinal);
            if (start < 0)
            {
                return null;
            }

            start += header.Length;
            var end = pem.IndexOf(footer, start, StringComparison.Ordinal) - start;
            if (end < 0)
            {
                return null;
            }

            return Convert.FromBase64String(pem.Substring(start, end));
        }

        /// <summary>
        /// Delete certs that match the provided issuer.  Used for cleaning up test certs.
        /// </summary>
        /// <param name="matcher"></param>
        internal static void DeleteCertsByIssuer(string issuerName)
        {
            X509Store store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            // Get a collection of our certs.
            var toRemove = new X509Certificate2Collection();
            foreach (var c in store.Certificates)
            {
                var issuer = c.IssuerName.Name;
                if (issuer.Contains(issuerName))
                {
                    toRemove.Add(c);
                }
            }

            store.RemoveRange(toRemove);
            store.Close();
        }

        internal static void InstallCert(X509Certificate2 cert)
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            store.Close();
        }
        internal static void InstallCert(string certFileName)
        {
            var cert = new X509Certificate2(certFileName);
            InstallCert(cert);
            return;
        }

        internal static void SetCertForPort(string certFile, int port)
        {
            X509Certificate2 serverCert = new X509Certificate2(certFile);
            var certHashString = Helpers.Hexify(serverCert.GetCertHash());

            var psi = new ProcessStartInfo("netsh");

            psi.Arguments = $"http add sslcert ccs=5556 certhash={certHashString} appid={{00112233-4455-6677-8899-AABBCCDDEEFF}}";
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.RedirectStandardError = true;
            var proc = Process.Start(psi); ;
            string op = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

        }
        /*
        static string ss = "MKADAgECAgUKCwwNDjAPBg0AAAAAAAAADoKAgKg4MGIxEDAOBgGYDAlSSW9UIENvcmUxCTAHBgH0DAJVUzFDMEEGNQCCgICrNIKAgKo4AIKAgK9cgoCAsACCgICrWACCgICvXIKAgLAAgoCAq1gAwIS7GYSb0etHDAhNU1JfVEVTVDAeFw0xNzAxMDEwMDAwMDBaFw0zNzAxMDEwMDAwMDBaMGQxEjAQBgGYDAtSSW9UIERldmljZTEJMAcGAfQMAlVTMUMwQQY1AIKAgKs0goCAqjgAgoCAr1yCgICwAIKAgKtYAIKAgK9cgoCAsACCgICrWADAhLsZhJvR60cMCE1TUl9URVNUMEwwBgYBaAYBkANCAASJ9eWD644UMAuBkFKWAd6Ja/PeEfr+noNBXYPeea17GDVUfqcbpJpwJ25xShKT5lPdRsQeaRcsOK+WLkqKMuuOozAwBgxogd2StG8Ag6rR/SgBAf8EMA==";
        internal static void CrackCert(string fileName)
        {
            var b = Base64.Decode(ss);

            DerSequence seq = (DerSequence)DerSequence.FromByteArray(b);


            return;
        }
        */
        
    }
}