using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;


namespace RIoT
{
    internal class RIoTDeviceInfo
    {
        internal byte[] FirmwareID;
        internal byte[] EncodedDeviceIDKey;
        internal X509Certificate2 Cert;
    }


    /// <summary>
    /// Decodes the RIoT Subject Alt Name extension.  todo: this uses bouncy castle: port
    /// to raw c#.
    /// </summary>
    class ExtensionDecoder
    {
        static string RIoTOid = "2.23.133.5.4.1";
        static string ecPubKeyOID = "1.2.840.10045.2.1";
        static string prime256v1Oid = "1.2.840.10045.3.1.7";
        static string sha256Oid = "2.16.840.1.101.3.4.2.1";
        static Oid SubjectAltNameOID = new Oid("2.5.29.17");

        static internal RIoTDeviceInfo Decode(string certFileName)
        {
            var cert = new X509Certificate2(certFileName);
            return Decode(cert);
        }

        static internal RIoTDeviceInfo Decode(X509Certificate2 aliasCert)
        {


            AsnEncodedData altNames = null;
            foreach (var ext in aliasCert.Extensions)
            {
                if (ext.Oid.Value != RIoTOid) continue;
                altNames = new AsnEncodedData(ext.Oid, ext.RawData);
            }
            // an AltName is mandatory
            if (altNames == null)
            {
                Helpers.Notify("Certificate does not have an altName field", true);
                return null;
            }
            // parse the extension: this is a collection of nested thus - 
            /*
             *  DER Sequence
                    ObjectIdentifier(1.2.3.4.5.6)                               <- RIoT Composite ID OID
                    DER Sequence
                        Integer(1)                                              <- Version number
                        DER Sequence                                            <- DeviceID public key
                            DER Sequence                                            (same encoding as in DeviceID cert)
                                ObjectIdentifier(1.2.840.10045.2.1)                 EC pubkey        
                                ObjectIdentifier(1.2.840.10045.3.1.7)               prime256
                            DER Bit String[65, 0]                                   key value
                        DER Sequence                                            <-  Encoded FWID
                            ObjectIdentifier(2.16.840.1.101.3.4.2.1)                sha256
                            DER Octet String[32]                                    FWID hash value
             * 
             * 
             * */

            try
            {
                DerSequence seq = (DerSequence)DerSequence.FromByteArray(altNames.RawData);
                //DerTaggedObject obj = (DerTaggedObject)seq[0];
                //DerSequence obj2 = (DerSequence)obj.GetObject();
                //var oid = (DerObjectIdentifier)obj2[0];
                //if (oid.Id != RIoTOid) return ParseError("Incorrect RIoT OID");

                
                var versionNumber = (DerInteger)seq[0];
                if (versionNumber.PositiveValue.IntValue != 1) return ParseError("Wrong version number");

                DerSequence obj4 = (DerSequence)seq[1];
                DerSequence obj5 = (DerSequence)obj4[0];
                var keyAlg1 = (DerObjectIdentifier)obj5[0];
                var keyAlg2 = (DerObjectIdentifier)obj5[1];
                if (keyAlg1.Id != ecPubKeyOID) return ParseError("Bad ECPubKey OID");
                if (keyAlg2.Id != prime256v1Oid) return ParseError("Bad curve OID");
                var key = (DerBitString)obj4[1];
                var obj4b = (DerSequence)seq[2];
                var hashAlg = (DerObjectIdentifier)obj4b[0];
                if (hashAlg.Id != sha256Oid) return ParseError("Bad fwid hash OID");
                var hash = (DerOctetString)obj4b[1];
                RIoTDeviceInfo deviceInfo = new RIoTDeviceInfo()
                {
                    FirmwareID = hash.GetOctets(),
                    EncodedDeviceIDKey = key.GetBytes(),
                    Cert = aliasCert
                };

                return deviceInfo;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.ToString());
                return null;
            }

        }
        static RIoTDeviceInfo ParseError(string error)
        {
            Helpers.Notify($"Extension parsing error: {error}", true);
            return null;
        }

        /// <summary>
        /// If a device presents a "bare" certificate rather than a full certificate chain, we have to 
        /// peform some steps that would normall be performed by the X509 chain builder.  Specifically, 
        /// the RIoT extension (above) encodes the DeviceID public key, but we have to check that this
        /// Alias Cert was actually signed by the corresponding DeviceID private key.  To do this we
        /// parse the Alias Cert to get:
        ///     The "to be signed" region (byte array)
        ///     The OID of the signature scheme
        ///     The signature block
        ///     
        /// The caller of this function can then check that the ALias Cert was indeed signed by the 
        /// device it claims to be from.
        /// </summary>
        /// <param name="aliasCert"></param>
        /// <returns></returns>
        static internal DecomposedCert Decompose(X509Certificate2 aliasCert)
        {
            var rawData = aliasCert.GetRawCertData();
            try
            {
                DerSequence seq = (DerSequence)DerSequence.FromByteArray(rawData);
                DerSequence tbs = (DerSequence)seq[0];
                DerSequence sigAlg = (DerSequence)seq[1];
                var sigAlgOid = (DerObjectIdentifier)sigAlg[0];

                DerBitString sigData = (DerBitString)seq[2];
                DerSequence sigSequence = (DerSequence) DerSequence.FromByteArray(sigData.GetOctets());
                var sig1 = (DerInteger)sigSequence[0];
                var sig2 = (DerInteger)sigSequence[0];

                var sig1Bytes = sig1.Value.ToByteArrayUnsigned();
                var sig2Bytes = sig1.Value.ToByteArrayUnsigned();

                Debug.Assert(sig1Bytes.Length == 32 && sig1Bytes.Length == 32);

                byte[] SignatureX = new byte[64];
                Array.Copy(sig1Bytes, 0, SignatureX, 0, 32);
                Array.Copy(sig2Bytes, 0, SignatureX, 32, 32);

                Debug.WriteLine("");

                DecomposedCert bits = new DecomposedCert
                {
                    Tbs = tbs.GetDerEncoded(),
                    OID = sigAlgOid.Id,
                    Signature = SignatureX
                };
                return bits;                
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.ToString());
                return null;
            }
        }

        

    }
    internal class DecomposedCert
    {
        internal byte[] Tbs;
        internal string OID;
        internal byte[] Signature;
    }
}
