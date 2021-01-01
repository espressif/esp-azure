/*
 * Microsoft Copyright, 2017
 * Author: pengland
 */
namespace DICETest
{
    using System;
    using System.Linq;
    using System.IO;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.X509.Extension;

    /// <summary>
    /// DICE Certificate and CSR validity checker.  This is not an exhaustive validation library for X509 certificates, but
    /// checks the mandatory fields created by DICE implementations, and smoke-tests the certificate chains that result.
    /// </summary>
    class CertChecker
    {
        static readonly string SigAlgName = "SHA-256withECDSA";
        private static string DICEExtensionOid = "2.23.133.5.4.1";
        private static int DICEExtensionVersionNumber = 1;
        private static int MinimumCertLifetimeInYears = 10;
        private static int serialNumMinBytes = 8;

        SubjectPublicKeyInfo PubKeyInfoFromDICEExtension=null;

        string[] PEMCertFile;
        /// <summary>
        /// First cert is always the Alias (leaf) cert
        /// </summary>
        X509Certificate[] Certs;
        int NumCerts;
        internal CertChecker()
        {
        }
        /// <summary>
        /// Specify the PEM file names for the certificates to be checked.  The first cert should be the Alias Cert, and the 
        /// subsequent certs should be in order "up the chain" to a self-signed cert (vendor/root or DeviceID)
        /// </summary>
        /// <param name="pemFileNames"></param>
        /// <returns></returns>
        internal bool SetCerts(string[] pemFileNames)
        {
            PEMCertFile = pemFileNames;
            NumCerts = PEMCertFile.Length;
            Certs = new X509Certificate[NumCerts];
            for(int j=0;j<NumCerts;j++)
            {
                try
                {
                    using (var reader = File.OpenText(PEMCertFile[j]))
                    {
                        Certs[j] = (X509Certificate)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                    }
                }
                catch(Exception e)
                {
                    Program.Print($"Failed to parse the certificate: {PEMCertFile[j]}", NotifyType.Error);
                    Program.Print($"Error is : {e.ToString()}", NotifyType.Error);
                    return false;
                }
            }
            return true;

        }

        /// <summary>
        /// This is the main certificate and certificate chain validation function.
        /// 
        /// Checks a DICE certificate chain.  The chain must always contain the Alias Cert and the DeiceID cert
        /// as the first two elements.  Zero or any number of vendor intermediate certs may follow.  THe last cert
        /// must always be self signed (either the vendor root-CA cert, or the DeviceID cert).
        /// </summary>
        /// <returns>All tests passed</returns>
        internal bool CheckChain()
        {
            bool ok = true;
            // check subject/issuer linkage (and print subjects)
            ok &= CheckSubjectIssuerLinkage();

            // check the the signatures good includign the self-signed root-cert
            ok &= CheckSigningLinkage();

            // check basic constraints for all certs
            ok &= CheckCaAndPathLengthConstraint();

            // Check the optional Authority Key Identifier linkage
            ok &= CheckAuthKeyIdentifierLinkage();

            // next check that the chain is well-formed using the .NET built-in validation routines
            // (i.e. not the bouncy-castle validator.)
            ok &= ChainChecker.CheckChain(Certs);

            // Now check the cert fields are all good for all of the certificates in the chain
            for (int j = 0; j < NumCerts; j++)
            {
                string tp = "";
                switch(j)
                {
                    case 0: tp = "Alias Cert"; break;
                    case 1: tp = "DeviceID Cert"; break;
                    default:
                        if (j == NumCerts - 1)
                        {
                            tp = "Vendor Root CA";
                        } else
                        {
                            tp = "Vendor Intermediate CA";
                        }
                        break;
                }
                Notify($"Checking {tp}: {Certs[j].SubjectDN.ToString()}");
                bool certOk = CheckCertFields(Certs[j], j);
                if(certOk)
                {
                    NotifySuccess("OK");
                }
                else
                {
                    Error("Certificate has errors");
                }
                ok &= certOk;
            }
            return ok;
        }

        /// <summary>
        /// Does basic validity checks for a CSR (is it properly self-signed)
        /// </summary>
        /// <param name="csrPEM"></param>
        /// <returns>CSR is properly signed</returns>
        internal static bool CheckCSR(string csrPEM)
        {
            Pkcs10CertificationRequest csr = null;
            try
            {
                using (var reader = File.OpenText(csrPEM))
                {
                    csr = (Pkcs10CertificationRequest)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                }
            }
            catch (Exception e)
            {
                Program.Print($"Failed to parse the csr: {csrPEM}", NotifyType.Error);
                Program.Print($"Error is : {e.ToString()}", NotifyType.Error);
                return false;
            }

            bool sigOk = csr.Verify();
            if(!sigOk)
            {
                Error("CSR signature did not verify");
                return false;
            }
            return true;
        }

        /// <summary>
        /// A PoP cert is a "fake" DeviceID cert containing a challenge subject common name.  To check this there must
        /// be two certs in the chain: the PoP cert and the vendor root cert.
        /// </summary>
        /// <param name="cn"></param>
        /// <returns>PoP cert is properly signed, and the subject common name is correct.</returns>
        internal bool CheckPopCert(string cn)
        {
            X509Name name=null;
            try
            {
                name = new X509Name(cn);
            }
            catch(Exception e)
            {
                Error($"Name {cn} is not a valid X509 Name (e.g. CN=XXXQQQ) {e.ToString()}");
                return false;
            }
            Notify("Checking PoP Cert");
            bool ok = CheckSigningLinkage();
            if(!ok)
            {
                return false;
            }

            var certSubject = Certs[0].SubjectDN;
            if(certSubject.ToString()!= name.ToString())
            {
                Error($"Cert subject is incorrect.  Should be {name.ToString()} but is {certSubject.ToString()}");
                return false;
            }
            return true;
        }

        /// <summary>
        /// Checks that the issuer of all certs in a chain matches the subject of the parent.
        /// </summary>
        /// <returns>The subject/issuer correspondence is correct</returns>
        internal bool CheckSubjectIssuerLinkage()
        {
            bool ok = true;
            Notify($"Checking Subject/Issuer Linkage");
            foreach (var c in Certs)
            {
                Notify($"    {c.SubjectDN.ToString()}");
            }
            if(Certs[NumCerts-1].SubjectDN.ToString() != Certs[NumCerts - 1].IssuerDN.ToString())
            {
                Error($"Root cert subject and issuer are different Subject:{Certs[NumCerts - 1].SubjectDN.ToString()} Issuer:{Certs[NumCerts - 1].IssuerDN.ToString()}");
                ok = false;
            }
            // alias to root
            for(int j=0;j<NumCerts-1;j++)
            {
                if (Certs[j].IssuerDN.ToString() != Certs[j+1].SubjectDN.ToString())
                {
                    Error($"Cert issuer is not issuer subject. Claimed issuer:{Certs[j].IssuerDN.ToString()}.\r\nActual Issuer:{Certs[j+1].SubjectDN.ToString()}");
                    ok = false;
                }
            }
            if(ok)
            {
                NotifySuccess("OK");
            }
            return ok;
        }

        /// <summary>
        /// Checks that the root cert is self signed, and that all other certs are propely signed by the issuer.
        /// </summary>
        /// <returns>Chain signing linkage is OK</returns>
        internal bool CheckSigningLinkage()
        {
            Notify($"Checking signature chains");

            bool ok = true;
            // alias to cert-before-root should be signed by parent
            for (int j = 0; j < NumCerts - 1; j++)
            {
                var target = Certs[j];
                var signer = Certs[j + 1];
                var signerPubKey = signer.GetPublicKey();
                try
                {
                    target.Verify(signerPubKey);
                }
                catch(Exception e)
                {
                    Error($"    Cert {target.SubjectDN.ToString()} is not properly signed by {signer.SubjectDN.ToString()}.  Error is {e.ToString()}");
                    ok = false;
                }
            }
            // The root should be self-signed
            var root = Certs[NumCerts - 1];
            var rootPubKey = root.GetPublicKey();
            try
            {
                root.Verify(rootPubKey);
            }
            catch (Exception)
            {
                Error($"Root cert is not properly self-signed.");
                ok = false;
            }
            if(ok)
            {
                NotifySuccess("OK");
            }
            return ok;
        }

        /// <summary>
        /// Authority Key Identifier is an optional field.  If present, it should be the key identifier of the parent.
        /// Absence of the field is a warning.  If present, bad linkage is an error.
        /// </summary>
        /// <returns></returns>
        internal bool CheckAuthKeyIdentifierLinkage()
        {
            bool ok = true;
            // alias to root
            for (int j = 0; j < NumCerts - 1; j++)
            {
                var signer = Certs[j + 1];
                var target = Certs[j];
                var akiData = target.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
                if(akiData ==null)
                {
                    Warning($"Certificate does not contain an Authority Key Identifier Extension: {target.SubjectDN.ToString()}");
                    continue;
                }
                if (akiData != null)
                {
                    var aki = new AuthorityKeyIdentifierStructure(akiData);
                    var signerKeyId = new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(signer.GetPublicKey()));
                    if(!signerKeyId.Equals(aki))
                    {
                        Error($"Authority Key Identifier does not match signer for certificate with subject: {target.SubjectDN.ToString()}");
                        ok = false;
                    }

                }
            }
            return ok;
        }

        /// <summary>
        /// Check that the CA fields and path length constraint allows a valid chain to be built
        /// </summary>
        /// <returns>Basic constraints are OK</returns>
        internal bool CheckCaAndPathLengthConstraint()
        {
            bool ok = true;
            // alias to root
            for (int j = 0; j < NumCerts - 1; j++)
            {
                var c = Certs[j];
                int basicConstraint = c.GetBasicConstraints();
                if(j==0)
                {
                    if(basicConstraint!=-1)
                    {
                        Error($"Alias Cert has basic constraint");
                        ok = false;
                    }
                }
                else
                {
                    if (basicConstraint < j-1)
                    {
                        Error($"Root or intermediate cert BasicConstraint is incorrect for {c.SubjectDN.ToString()}.  Require >{j-1}, but it is {basicConstraint}");
                        ok = false;
                    }
                }
            }
            return ok;
        }

        /// <summary>
        /// Checks the fields in the certificate are OK
        /// </summary>
        /// <param name="c">The certifcate to be checked</param>
        /// <param name="offsetFromAlias">How far up the chain the cert is (alias=zero)</param>
        /// <returns>The cert fields are good</returns>
        bool CheckCertFields(X509Certificate c, int offsetFromAlias)
        {
            bool ok = true;
            // processing depends on the type of cert
            bool isAlias = offsetFromAlias == 0;
            bool isCa = offsetFromAlias != 0;
            bool isAliasOrDevId = offsetFromAlias <= 1;

            ok&=CheckAlgs(c);
            ok&=CheckKeyUsage(c, isCa);
            ok&=CheckExtendedKeyUsage(c, isCa) ;
            ok&=CheckValidityDates(c);

            if (isAlias)
            {
                ok&= CheckDICEExtension(c) ;
            }
            if (isAliasOrDevId)
            {
                ok&= CheckSerialNumber(c);
            }

            return ok;
        }

        /// <summary>
        /// Checks the signature algorithm (only P256SHA256, at this time)
        /// </summary>
        /// <param name="c">Certificate to be checked</param>
        /// <returns>Algorithm set is OK</returns>
        bool CheckAlgs(X509Certificate c)
        {
            if (!CheckExpected("Signature algorithm", SigAlgName, c.SigAlgName)) return false;
            return true;
        }
        
        /// <summary>
        /// Parses and checks contents of the DICE extension
        /// </summary>
        /// <param name="c">Certificate to validate</param>
        /// <returns>Extension is well formed</returns>
        bool CheckDICEExtension(X509Certificate c)
        {
            var criticalOids = c.GetCriticalExtensionOids();

            if (criticalOids.Contains(DICEExtensionOid))
            {
                Error("DICE extension is marked critical and should be non-critical");
                return false;
            }

            var nonCriticalOids = c.GetNonCriticalExtensionOids();
            if(!nonCriticalOids.Contains(DICEExtensionOid))
            {
                Error("DICE extension not found");
                return false;
            }
            var diceExtension = c.GetExtensionValue(new DerObjectIdentifier(DICEExtensionOid));
            try
            {
                DerOctetString envelope = (DerOctetString) DerOctetString.FromByteArray(diceExtension.GetEncoded());
                DerSequence seq = (DerSequence) DerSequence.FromByteArray(envelope.GetOctets());
                // first field is version number
                var versionNumber = (DerInteger)seq[0];
                if (versionNumber.PositiveValue.IntValue != 1)
                {
                    Error($"DICE Extension has Wrong version number.  Expecing {DICEExtensionVersionNumber}, cert contains {versionNumber.ToString()}");
                    return false;
                }
                // second field is DeviceID
                var devIdPubKey = SubjectPublicKeyInfo.GetInstance(seq[1]);
                // will check it's good later
                PubKeyInfoFromDICEExtension = devIdPubKey;

                // third field contains {hashOid, hashVal} 
                var hashEnvelope = (DerSequence)seq[2];
                var hashAlg = (DerObjectIdentifier)hashEnvelope[0];
                if (hashAlg.Id != NistObjectIdentifiers.IdSha256.ToString())
                {
                    Error("DICE Extension hash alg is wrong.  ");
                    return false;
                }
                var hashVal = (DerOctetString)hashEnvelope[1];
                if (hashVal.GetOctets().Length != 32)
                {
                    Error("DICE Extension hash value length is wrong.  ");
                    return false;
                }
            }
            catch (Exception e)
            {
                Error($"Failed to parse the DICE extension.  Parsing exception was {e.ToString()}");
                return false ;
            }

            return true;
        }

        /// <summary>
        /// Sanity checks the Key Usage certificate extension
        /// </summary>
        /// <param name="c">Certificate to validate</param>
        /// <param name="isCA">Whether the cert is a CA cert (intermediate or root)</param>
        /// <returns>Key Usage is OK</returns>
        bool CheckKeyUsage(X509Certificate c, bool isCA)
        {
            int requiredFlags = (isCA? KeyUsage.KeyCertSign : 0);

            // Currently none of the reference implemtations use these fields.  
            int badFlags = KeyUsage.DataEncipherment | KeyUsage.CrlSign | KeyUsage.DecipherOnly | KeyUsage.EncipherOnly | 
                KeyUsage.KeyAgreement | KeyUsage.KeyEncipherment | KeyUsage.NonRepudiation;

            bool flagsOk = true;

            try
            {
                var keyUsage= c.GetKeyUsage();
                if(keyUsage==null)
                {
                    Error($"KeyUsage is missing.");
                    return false;
                }
                if (keyUsage.Length>9)
                {
                    Error($"Unsupported KeyUsage.  This usually means that DecipherOnly is asserted, which is an error");
                    return false;
                }
                for (int j = 0; j < 9; j++)
                {
                    if (j >= keyUsage.Length) break;
                    int flag = 1 << (7-j);
                    if ((requiredFlags & flag) != 0)
                    {
                        if (!keyUsage[j])
                        {
                            Error($"Required key usage NOT asserted: {KeyUsageFlagToString(flag)}");
                            flagsOk = false;
                        }
                    }
                    if ((badFlags & flag) != 0)
                    {
                        if (keyUsage[j])
                        {
                            Error($"Bad key usage asserted: {KeyUsageFlagToString(flag)}");
                            flagsOk = false;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Error("Failed to parse the flags extension:" + e.ToString());
                flagsOk = false;
            }
            return flagsOk;
        }

        /// <summary>
        /// Checks the extended key usage for CA (including DeviceID) and alias certs
        /// </summary>
        /// <param name="c">The certififcate to check</param>
        /// <param name="isCa">Whether the cert is a root or intermediate CA cert</param>
        /// <returns>Extended usage is OK</returns>
        bool CheckExtendedKeyUsage(X509Certificate c, bool isCa)
        {
            var extendedKeyUsage = c.GetExtendedKeyUsage();
            var setUsage = "";
            if (isCa)
            {
                if (extendedKeyUsage!= null)
                {
                    foreach (var s in extendedKeyUsage) setUsage += s.ToString() + " ";
                    Error("One of more ExtendedKeyUsage asserted on non-alias certificate:" + setUsage);
                    return false;
                }
                return true;
            }
            // else is the alias
            foreach (var s in extendedKeyUsage) setUsage += s.ToString() + " ";
            {
                if (extendedKeyUsage.Count != 1)
                {
                    Error("Too many ExtendedKeyUsage asserted for non-alias certificate:" + setUsage);
                    return false;
                }
                if (extendedKeyUsage[0].ToString() != KeyPurposeID.IdKPClientAuth.ToString())
                {
                    Error("Extended Key Usage ClientAuth not asserted");
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Basic validity period checks
        /// </summary>
        /// <param name="c">Certificate to validate</param>
        /// <returns>Validity period is OK</returns>
        bool CheckValidityDates(X509Certificate c)
        {
            TimeSpan MinimumCertLifetime = new TimeSpan(MinimumCertLifetimeInYears * 365, 0, 0, 0, 0); 

            if(!c.IsValidNow)
            {
                Warning("Certificate is not valid now");
                return true;
            }
            TimeSpan certLifetime = c.NotAfter - DateTime.Now;
            if (certLifetime<MinimumCertLifetime)
            {
                double actualLifeInYears = certLifetime.TotalDays / 365;
                Warning($"Certificate lifetime is {actualLifeInYears} years, which is less than the recommended {MinimumCertLifetimeInYears} years");
                return true;
            }
            return true;
        }

        /// <summary>
        /// Device and Alias cert serial numbers must be "long enough" integers
        /// </summary>
        /// <param name="c"></param>
        /// <returns></returns>
        bool CheckSerialNumber(X509Certificate c)
        {
            BigInteger sn = c.SerialNumber;
            var snBytes = sn.ToByteArray();
            int snNumBytes = snBytes.Length;
            if(snNumBytes<serialNumMinBytes)
            {
                Error($"Serial number is only {snNumBytes} bytes, but {serialNumMinBytes} is recommended");
                return false;
            }
            int numZeroBytes = snBytes.Count(x => x == 0);
            if (numZeroBytes>=3)
            {
                Warning($"Serial number has {numZeroBytes} zeros.  Is it random?");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Helper checker and notification function.
        /// </summary>
        /// <param name="category">Error message if expected!=value</param>
        /// <param name="expected"></param>
        /// <param name="actual">Actual data</param>
        /// <returns>Expected==actual</returns>
        bool CheckExpected(string category, string expected, string actual)
        {
            if (expected == actual) return true;
            Error($"Bad field: {category}.  Expected={expected}, Actual={actual}");
            return false;
        }

        /// <summary>
        /// ASN.1 Key Usage value-to-string translator
        /// </summary>
        /// <param name="flag"></param>
        /// <returns></returns>
        static string KeyUsageFlagToString(int flag)
        {
            switch (flag)
            {
                case (1 << 7): return "DigitalSignature";
                case (1 << 6): return "NonRepudiation";
                case (1 << 5): return "KeyEncipherment";
                case (1 << 4): return "DataEncipherment";
                case (1 << 3): return "KeyAgreement";
                case (1 << 2): return "KeyCertSign";
                case (1 << 1): return "CrlSign";
                case (1 << 0): return "EncipherOnly";
                case (1 << 15): return "DecipherOnly";
                default: return $"Undefined flag at bit position {flag}";
            }
        }

        /// <summary>
        /// Print/Log an error
        /// </summary>
        /// <param name="error">String to print</param>
        static void Error(string error)
        {
            Program.Print(error, NotifyType.Error);
            return;
        }
        /// <summary>
        /// Print/log a warning
        /// </summary>
        /// <param name="warning">Warning to print</param>
        static void Warning(string warning)
        {
            Program.Print(warning, NotifyType.Warning);
            return;
        }
        /// <summary>
        /// Print/log a notification message
        /// </summary>
        /// <param name="message">Message to print</param>
        static void Notify(string message)
        {
            Program.Print(message, NotifyType.Notify);
            return;
        }
        /// <summary>
        /// Print/log a success notification 
        /// </summary>
        /// <param name="message">Message to print</param>
        static void NotifySuccess(string message)
        {
            Program.Print(message, NotifyType.Success);
            return;
        }

    }
}
