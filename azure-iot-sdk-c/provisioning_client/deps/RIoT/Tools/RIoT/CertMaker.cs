using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;

namespace RIoT
{
    class DeviceBundle
    {
        internal AsymmetricCipherKeyPair AliasKeyPair;
        internal X509Certificate AliasCert;
        internal AsymmetricKeyParameter DeviceIDPublic;
    }
    /// <summary>
    /// A certificate and a key pair
    /// </summary>
    internal class CertBundle
    {
        internal X509Certificate Certificate;
        internal AsymmetricCipherKeyPair KeyPair;
    }



    class CertMaker
    {
        internal CertMaker(string dir)
        {
            if(!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }

        internal void CertifyExisting(int chainLen)
        {
            DeviceBundle bundle = new DeviceBundle();

            bundle.AliasCert = (X509Certificate) Helpers.ReadPemObject(ToPath(Program.AliasCert));
            bundle.DeviceIDPublic = (AsymmetricKeyParameter)Helpers.ReadPemObject(ToPath(Program.DeviceIDPublic));

            bundle.AliasKeyPair = (AsymmetricCipherKeyPair)Helpers.ReadPemObject(ToPath(Program.AliasKey));

            //ECPrivateKeyParameters opriv = (ECPrivateKeyParameters) Helpers.ReadPemObject(ToPath("AliasPrivate.PEM"));
            //ECPublicKeyParameters opub = (ECPublicKeyParameters)Helpers.ReadPemObject(ToPath("AliasPublic.PEM"));
            //AsymmetricCipherKeyPair kpx = new AsymmetricCipherKeyPair(opub, opriv);
            //bundle.AliasKeyPair = kpx;
            //var privKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(oo);
            //oo.
            //var  kp = PrivateKeyInfoFactory.CreatePrivateKeyInfo(oo);

            //AsymmetricCipherKeyPair kp = (AsymmetricCipherKeyPair)KeyIn.CreatePrivateKeyInfo(oo);

            //ECPrivateKeyParameters parms = (ECPrivateKeyParameters) Helpers.ReadPemObject(ToPath(Program.AliasKey));
            //bundle.AliasKeyPair = new A

            MakeCertChain(bundle, chainLen, 0);
        }

        internal void CertifyExistingForJava(int chainLen)
        {
            DeviceBundle bundle = new DeviceBundle();

            bundle.AliasCert = (X509Certificate)Helpers.ReadPemObject(ToPath(Program.AliasCert));
            bundle.DeviceIDPublic = (AsymmetricKeyParameter)Helpers.ReadPemObject(ToPath(Program.DeviceIDPublic));

            // The current Java implementation stores the public and provate keys separately.  Put them back 
            // together
            ECPrivateKeyParameters opriv = (ECPrivateKeyParameters)Helpers.ReadPemObject(ToPath("AliasPrivate.PEM"));
            ECPublicKeyParameters opub = (ECPublicKeyParameters)Helpers.ReadPemObject(ToPath("AliasPublic.PEM"));
            AsymmetricCipherKeyPair kpx = new AsymmetricCipherKeyPair(opub, opriv);
            Helpers.WritePEMObject(ToPath(Program.AliasKey), kpx);

            bundle.AliasKeyPair = (AsymmetricCipherKeyPair)Helpers.ReadPemObject(ToPath(Program.AliasKey));


            MakeCertChain(bundle, chainLen, 0);
        }


        internal void CertifyExistingFromCsr(int chainLen)
        {

            var req = (Pkcs10CertificationRequest)Helpers.ReadPemObject(ToPath(Program.DeviceIDCSR));
            //var req = (Pkcs10CertificationRequest)Helpers.ReadPemObject(fileName);

            if (!req.Verify())
            {
                Helpers.Notify("PKCS10 csr is not properly self-signed");
                return;
            }
            // todo: should propagate the subject in the CSR into the DeviceID certificate.

            var info = req.GetCertificationRequestInfo();
            AsymmetricKeyParameter deviceIdKey = PublicKeyFactory.CreateKey(info.SubjectPublicKeyInfo);

            DeviceBundle bundle = new DeviceBundle();

            bundle.AliasCert = (X509Certificate)Helpers.ReadPemObject(ToPath(Program.AliasCert));
            bundle.DeviceIDPublic = (AsymmetricKeyParameter)deviceIdKey;
            bundle.AliasKeyPair = (AsymmetricCipherKeyPair)Helpers.ReadPemObject(ToPath(Program.AliasKey));

            if(bundle.AliasCert.IssuerDN.ToString() != info.Subject.ToString())
            {
                Helpers.Notify("CSR Subject Name does not match Alias Certificate Issuer Name: Chain will not build.", true);
                return;
            }
            // todo (maybe).  Check that the Alias extension claimed DeviceID matches the DeviceID CSR key.

            MakeCertChain(bundle, chainLen, 0);
        }


        internal void MakeNew(int chainLen, bool refresh, int fwidSeed)
        {
            var bundle = MakeAliasCert(refresh, fwidSeed);
            MakeCertChain(bundle, chainLen, fwidSeed);
        }

        /// <summary>
        /// Make a new Alias Cert.  If refresh=false, a new DevID and Alias are created.  If refresh=true
        /// then just the Alias is created and re-certified using the stored DevID key.
        /// </summary>
        /// <param name="refresh"></param>
        /// <returns></returns>
        internal DeviceBundle MakeAliasCert(bool refresh, int fwidSeed)
        {
            DateTime now = DateTime.Now;
            byte[] fwid = Helpers.HashData(new byte[1] { (byte) fwidSeed }, 0,  1);

            const int keyStrength = 256;
            CryptoApiRandomGenerator rg = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(rg);
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair devIdKey = null;
            if (refresh)
            {
                devIdKey = (AsymmetricCipherKeyPair)Helpers.ReadPemObject(ToPath(Program.DeviceIDPrivate));
            }
            else
            {
                devIdKey = keyPairGenerator.GenerateKeyPair();
            }

            // test - remove
            var oids = new List<Object>() { X509Name.UnstructuredName };
            var values = new List<Object>() { "ljkljljklkjlkjlkjlkjlkjlkjlkjlkjlkjljklkjlkjlkjlkjljk" };
            X509Name name = new X509Name(oids, values);



            AsymmetricCipherKeyPair aliasKey = keyPairGenerator.GenerateKeyPair();

            // make a string name based on DevID public.  Note that the authoritative information 
            // is encoded in the RIoT-extension: this is just for quick-and-dirty device identification.
            var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(devIdKey.Public);
            byte[] pubEncoded = pubInfo.GetDerEncoded();
            var pubHashed = Helpers.HashData(pubEncoded, 0, pubEncoded.Length);
            var shortNameBytes = Helpers.CopyArray(pubHashed, 0, 8);
            var shortNameString = Helpers.Hexify(shortNameBytes);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            var serialNumber = new byte[8];
            rg.NextBytes(serialNumber);
            serialNumber[0] &= 0x7F;
            certGen.SetSerialNumber(new BigInteger(serialNumber));
            // The important name-related stuff is encoded in the RIoT extension
            certGen.SetIssuerDN(new X509Name($"CN=[I]DevID:{shortNameString}, O=MSR_TEST, C=US"));
            // test REMOVE
            //certGen.SetSubjectDN(name);
            certGen.SetSubjectDN(new X509Name($"CN=[S]DevID:{shortNameString}, O=MSR_TEST, C=US"));
            certGen.SetNotBefore(now);
            certGen.SetNotAfter(now + new TimeSpan(365 * 10, 0, 0, 0, 0));
            certGen.SetPublicKey(aliasKey.Public);

            // Add the extensions (todo: not sure about KeyUsage.DigitalSiganture
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                ExtendedKeyUsage.GetInstance(new DerSequence(KeyPurposeID.IdKPClientAuth)));
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            AddRIoTExtension(certGen, fwid, devIdKey);

            // sign it
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", devIdKey.Private, random);
            var certificate = certGen.Generate(signatureFactory);
            // and return the bundle
            DeviceBundle bundle = new DeviceBundle
            {
                AliasCert = certificate,
                DeviceIDPublic = devIdKey.Public,
                AliasKeyPair = aliasKey
            };

            // Just the AliasCert
            Helpers.WritePEMObject(ToPath(Program.AliasCert), bundle.AliasCert);
            // The Alias Key Pair
            Helpers.WritePEMObject(ToPath(Program.AliasKey), bundle.AliasKeyPair);
            // The encoded DevID
            Helpers.WritePEMObject(ToPath(Program.DeviceIDPublic), bundle.DeviceIDPublic);
            // DeviceIDPrivate (just for the update demo)
            Helpers.WritePEMObject(ToPath(Program.DeviceIDPrivate), devIdKey.Private);

            return bundle;
        }


        internal void MakeCertChain(DeviceBundle bundle, int chainLen, int fwidSeed)
        {
            var aliasCert = bundle.AliasCert;

            DateTime now = DateTime.Now;
            byte[] fwid = Helpers.HashData(new byte[1] { 0 }, 0, 1);
            const int keyStrength = 256;
            CryptoApiRandomGenerator rg = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(rg);
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            // Starting the loop we have a (not yet certified) DeviceID public key
            // and the Issuer of the Alias Cert (which we want to be the DevID-cert DN.)

            List<X509Certificate> certChain = new List<X509Certificate>();

            var lastCertIssuer = aliasCert.IssuerDN;
            var lastPubKey = bundle.DeviceIDPublic; ;
            AsymmetricCipherKeyPair lastKeyPair = null;
            for (int j = 0; j < chainLen; j++)
            {
                bool rootCert = j == chainLen - 1;
                bool lastButOne = j == chainLen - 2;
                AsymmetricCipherKeyPair caKey = keyPairGenerator.GenerateKeyPair();

                X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
                certGen.SetSerialNumber(new BigInteger(new byte[] { 1, 2, 3, 4, 5 }));
                var issuerDn = lastButOne ?
                    new X509Name($"CN=Vendor Root CA O=MSR_TEST, C=US") :
                    new X509Name($"CN=Vendor Intermediate CA {j}, O=MSR_TEST, C=US");
                if (rootCert)
                {
                    issuerDn = lastCertIssuer;
                }

                certGen.SetIssuerDN(issuerDn);
                certGen.SetSubjectDN(lastCertIssuer);
                certGen.SetNotBefore(now);
                certGen.SetNotAfter(now + new TimeSpan(365 * 10, 0, 0, 0, 0));
                certGen.SetPublicKey(lastPubKey);



                int pathLengthConstraint = j + 1;
                certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(pathLengthConstraint));
                certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign));
                X509Certificate certificate;

                if (rootCert)
                {
                    ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", lastKeyPair.Private, random);
                    certificate = certGen.Generate(signatureFactory);
                }
                else
                {
                    ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", caKey.Private, random);
                    certificate = certGen.Generate(signatureFactory);
                }


                lastCertIssuer = certificate.IssuerDN;
                lastPubKey = caKey.Public;
                lastKeyPair = caKey;
                certChain.Add(certificate);

            }


            // Chain including root, but not AliasCert.  NOTE, finishes with CA
            Helpers.WritePEMObjects(ToPath(Program.DeviceCertChain), certChain.ToArray());
            // cert chain including AliasCert (alias cert is first.  CA is last)
            JoinFiles(Program.AliasCert, Program.DeviceCertChain, Program.DeviceCertChainIncAlias);

            // just the device CA (for the server)
            Helpers.WritePEMObject(ToPath("DeviceCA.pem"), certChain.Last());


            // Now make some certs for the server to use
            string serverCaName = "CN=Server CA, C=US, O=MSR_TEST";
            string serverName = "CN=Server Cert, C=US, O=MSR_TEST";

            var serverCA = MakeCertInternal(serverCaName, serverCaName, true, null, null, 1);
            var serverCert = MakeCertInternal(serverCaName, serverName, false, serverCA.KeyPair, null, 0);

            Helpers.WritePEMObject(ToPath(Program.ServerCA), serverCA.Certificate);
            Helpers.WritePEMObjects(ToPath(Program.ServerChain), new Object[] { serverCA.Certificate, serverCert.Certificate });
            //Helpers.WritePEMObject(ToPath("T0_ServerCAKey.PEM", serverCA.KeyPair);
            Helpers.WritePEMObject(ToPath(Program.ServerCert), serverCert.Certificate);
            Helpers.WritePEMObject(ToPath(Program.ServerKey), serverCert.KeyPair);

            // OpenSSL needs a file with the Device CA AND the server CA
            JoinFiles(Program.DeviceCertChain, Program.ServerCA, Program.DeviceCertChainAndServerCA);

            // OpenSSL test scripts - 

            // print a cert
            // openssl x509 -text -in T0_ServerCA.pem

            // Just verify the client chain
            // openssl verify -purpose sslclient -CAfile T0_DeviceCertChain.PEM DeviceAliasCert.PEM

            // Just verify the server chain
            // openssl verify -purpose sslserver -CAfile T0_ServerCA.PEM T0_ServerCert.PEM


            // openssl s_client -connect localhost: 5556 - cert T0_AliasCert.PEM - key T0_AliasKey.PEM - CAfile T0_DeviceCertChainAndServerCA.PEM
            // openssl s_client -connect localhost:5556 -cert T0_AliasCert.PEM -key T0_AliasKey.PEM -CAfile T0_DeviceCertChain.PEM
            // openssl s_server -cert T0_ServerCert.PEM -key T0_ServerKey.PEM -CAfile T0_DeviceCertChainAndServerCA.PEM -status_verbose -verify 10 -rev -accept 5556

            return;

        }


        void AddRIoTExtension(X509V3CertificateGenerator certGen, byte[] fwid, AsymmetricCipherKeyPair devIdKey)
        {
            DerObjectIdentifier extensionTag = new DerObjectIdentifier(Program.DeviceIdOid);
            DerOctetString fwId = new DerOctetString(fwid);

            var TaggedDevID = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(devIdKey.Public);

            // {hashAlgId,fwidHash}
            var TaggedFWID = new DerSequence(
                new Asn1Encodable[]
                {
                    NistObjectIdentifiers.IdSha256,
                    new DerOctetString(fwid)
                });

            // {1, devId, fwId}
            var EncodedRIoTIdentity = new DerSequence(
                new Asn1Encodable[]
                {
                    new DerInteger(1),  // version number
                    TaggedDevID,
                    TaggedFWID
                });

            // {riotOid, encodedIdentity}
            var TaggedEncodedRIoTID = new DerSequence(
                new Asn1Encodable[]
                {
                    new DerObjectIdentifier(Program.DeviceIdOid),
                    EncodedRIoTIdentity
                });


            byte[] ttt = TaggedEncodedRIoTID.GetDerEncoded();
            Debug.WriteLine(Helpers.Hexify(ttt));

            Debug.WriteLine(Asn1Dump.DumpAsString(TaggedEncodedRIoTID));

            certGen.AddExtension(
                X509Extensions.SubjectAlternativeName.Id,
                true,
                new GeneralNames(
                    new GeneralName(GeneralName.OtherName, TaggedEncodedRIoTID)));
        }


        private static CertBundle MakeCertInternal(
                string issuerName, string subjectName,
                bool isCA,
                AsymmetricCipherKeyPair signerKey = null,
                AsymmetricCipherKeyPair certKey = null,
                int pathLengthConstraint = 0)
        {
            const int keyStrength = 256;
            CryptoApiRandomGenerator rg = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(rg);
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            // make a new ECC key pair.  The pubKey will go in the cert.  The private key may or may
            // not be used for signing, depending on whether the caller provides a signing key.
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair newKey = keyPairGenerator.GenerateKeyPair();

            if (certKey != null)
            {
                newKey = certKey;
            }

            certGen.SetPublicKey(newKey.Public);
            BigInteger serialNumber = new BigInteger(new byte[] { 2, 3, 4 });
            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(new X509Name(issuerName));
            certGen.SetSubjectDN(new X509Name(subjectName));

            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore + new TimeSpan(365, 0, 0, 0);

            certGen.SetNotBefore(notBefore);
            certGen.SetNotAfter(notAfter);

            if (pathLengthConstraint != 0)
            {
                // then we want it to be a CA.  Using this constructor sets CA true AND sets the path length
                certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(pathLengthConstraint));
            }
            else
            {
                certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                    ExtendedKeyUsage.GetInstance(new DerSequence(KeyPurposeID.IdKPServerAuth)));
            };

            // Sign the cert
            var signingKey = (signerKey != null) ? signerKey : newKey;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", signingKey.Private, random);

            var certificate = certGen.Generate(signatureFactory);

            // and return the bundle
            var bundle = new CertBundle() { Certificate = certificate, KeyPair = newKey };
            return bundle;
        }


        string ToPath(string fileName)
        {
            return Program.ToPath(fileName);
        }

        void JoinFiles(string f1, string f2, string opFile)
        {
            File.Copy(ToPath(f1), ToPath(opFile), true);
            File.AppendAllText(ToPath(opFile), File.ReadAllText(ToPath(f2)));
            return;
        }

        static void TestCode()
        {
            var oids = new List<Object>() { X509Name.UnstructuredName };
            var values = new List<Object>() { "ljkljljklkjlkjlkjlkjlkjlkjlkjlkjlkjljklkjlkjlkjlkjljk"};
            X509Name name = new X509Name(oids, values);


        }


    }
}
/*
// Make a BCRYPT_ECCKEY_BLOB structure
// #define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345  // ECS2
uint BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345;
ECPublicKeyParameters aliasPub = (ECPublicKeyParameters)bundle.AliasKeyPair.Public;
ECPrivateKeyParameters aliasPriv = (ECPrivateKeyParameters)bundle.AliasKeyPair.Private;

var xx = aliasPub.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
var yy = aliasPub.Q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned();
var dd = aliasPriv.D.ToByteArrayUnsigned();

byte[] magic = BitConverter.GetBytes(BCRYPT_ECDSA_PRIVATE_P256_MAGIC);
byte[] size = BitConverter.GetBytes(3 * 32);
byte[] ecBlob = new byte[32 * 3 + 4 + 4];

Array.Copy(magic, 0, ecBlob, 0, 4);
Array.Copy(size, 0, ecBlob, 4, 4);
Array.Copy(xx, 0, ecBlob, 8, 32);
Array.Copy(yy, 0, ecBlob, 8+32, 32);
Array.Copy(dd, 0, ecBlob, 8+64, 32);

File.WriteAllBytes("P0_EcBlob.BIN", ecBlob);

Debug.WriteLine("");
foreach(var b in ecBlob)
{
    Debug.Write($"0x{b:X},");

}
Debug.WriteLine("");
*/

