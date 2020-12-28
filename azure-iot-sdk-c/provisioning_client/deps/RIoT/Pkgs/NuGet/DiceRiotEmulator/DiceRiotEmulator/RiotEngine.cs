// <copyright file="RIoTEngine.cs" company="Microsoft">
// Copyright (c) Microsoft. All rights reserved.
// </copyright>

namespace DiceRiotEmulator
{
    using System;
    using System.Collections;
    using System.IO;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;

    /// <summary>
    /// DICE/RIoT simulator.
    /// Creates debug/test versions of the keys and certificates that would be created by a real RIoT device.
    /// </summary>
    public class RIoTEngine
    {
        // Crypto parameters (note: these are interdependent)

        /// <summary>
        /// ECC key length
        /// </summary>
        private static int rKeyStrength = 256;

        /// <summary>
        /// Signature scheme
        /// </summary>
        private static string rSigSch = "SHA256withECDSA";

        /// <summary>
        /// Signature scheme OID
        /// </summary>
        private static DerObjectIdentifier rSignatureOID = X9ObjectIdentifiers.ECDsaWithSha256;

        /// <summary>
        /// Algorithm used to calculate the FWID
        /// </summary>
        private static DerObjectIdentifier rFwidAlg = NistObjectIdentifiers.IdSha256;

        // Simulated device and firmware parameters

        /// <summary>
        /// Simulated RIoT Core measurement
        /// </summary>
        private static byte[] rDigest = HexToByteArray("b5859493661e2eae9677c55d590b9294e094abafd740787e050dfe6d859053a0");

        /// <summary>
        /// Seed for deterministic(and simulated) "root" CA signing key pair
        /// </summary>
        private static byte[] rR00t = HexToByteArray("e3e7c713573fd9c8b8e1eaf453f1561502f071c05349c8dae626a90b1788e570");

        // Certificate fields.  The guid is replaced with a per-device GUID
        private static X509Name rRootCertSubject = new X509Name($"CN=RIoT R00t,O=MSR_TEST,C=US");
        private static X509Name rDeviceCertSubject = new X509Name($"CN=Core:guid,O=MSR_RIOT_TEST_DEVID,C=US");
        private static X509Name rAliasCertSubject = new X509Name("CN=Alias:guid,O=MSR_RIOT_TEST_ALIAS,C=US");

        /// <summary>
        /// DICE/RIoT extension OID
        /// </summary>
        private static string rExtensionOID = "2.23.133.5.4.1";

        /// <summary>
        /// The path length constraint for the self-signed DeviceID certificate. Increase
        /// this if the Alias Cert will certify additional keys(Alias Certificate attributes
        /// will also have to be modified.)
        /// </summary>
        private static int rPathLenConstraint = 1;

        /// <summary>
        /// Certificate validity start time (all certs)
        /// </summary>
        private static DateTime startTime = new DateTime(2017, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Certificate validity end time (all certs)
        /// </summary>
        private static DateTime endTime = new DateTime(3017, 12, 31, 23, 59, 59, DateTimeKind.Utc);

        /// <summary>
        /// Seed for the seeded pseudorandom sequences for key-gen, signing, and guid-gen
        /// (vendor CA/PKI)
        /// </summary>
        private static byte[] rootSeed;

        /// <summary>
        /// Seed for the seeded pseudorandom sequences for key-gen, signing, and guid-gen
        /// (never changes for a given device)
        /// </summary>
        private static byte[] devIdSeed;

        /// <summary>
        /// Seed for the seeded pseudorandom sequences for key-gen, signing, and guid-gen
        /// Changes on firmware update
        /// </summary>
        private static byte[] aliasSeed;

        /// <summary>
        /// Deterministic RNGs are used for key generation and signing.  SeedUsage
        /// adds additional seed data when DigestRandomGenerator is seeded so that
        /// the same seed can be used for different purposes.  For each seed, each
        /// SeedUsage value MUST NOT be used more than once.
        /// </summary>
        private enum SeedUsage
        {
            KeyGeneration,
            GuidGeneration,
            Signing,
            SelfSigning,
            CSR
        }

        /// <summary>
        /// Creates a certificate using the vendor/root key containing the challengeCommonName as the 
        /// subject.  Proof-of-possession of the vendor/root key is required to enroll a root certificate
        /// with the Azure Device Provisioning Service.
        /// </summary>
        /// <param name="">The challenge common name "nonce"</param>
        /// <returns>The signed challengeCommonName</returns>
        public static string CreateDevIDPoP(DeviceAuthBundle bundle, string challengeCommonName)
        {
            rDeviceCertSubject = new X509Name(challengeCommonName);
            var rootKey = new AsymmetricCipherKeyPair(bundle.RootCredential.PubKey, bundle.RootCredential.PrivKey);
            var rootSigningSeed = Hash(Hash(rR00t));
            var challengePoPCert = CreateDeviceCert(rootKey, bundle.DeviceIDCredential.PubKey, rootSigningSeed);
            var challengePoPCertPEM = DerToPem("CERTIFICATE", challengePoPCert);
            return challengePoPCertPEM;
        }

        /// <summary>
        /// Create keys and certificates
        /// </summary>
        /// <param name="uds">Per-device Unique Device Secret</param>
        /// <param name="fwid">Hash of firmware</param>
        /// <returns>The keys and certificates for the device</returns>
        public static DeviceAuthBundle CreateDeviceAuthBundle(byte[] uds, byte[] fwid)
        {
            if ((uds.Length != 32) || (fwid.Length != 32))
            {
                throw new ArgumentException("UDS and FWID must be 32-bytes in length");
            }

            DeviceAuthBundle authBundle = new DeviceAuthBundle();

            // In a real (non-emulated) DICE system, the CDI (compound device identity) would be
            // created by the SoC at startup, or calculated by ROM-based code very early in boot.
            // Here we simulate CDI creation based on a seed (the UDS, or Unique Device Secret)
            // provided by the caller.
            byte[] cdi = DICE.GetCDI(uds, rDigest);

            // Real DICE/RIoT Systems create keys and certificates on boot based on seeds.  The seeds
            // can change on various sorts of software update, but otherwise the keys and certificates
            // remain the same.
            rootSeed = Hash(rR00t);
            devIdSeed = Hash(cdi);
            aliasSeed = Hash(devIdSeed, fwid);

            // Vendor CA root key
            var rootKey = DeriveEccKey(rootSeed);

            // DeviceID key (should never change, but should be different for each device)
            var deviceID = DeriveEccKey(devIdSeed);

            // Device GUID (should never change, but should be different for each device)
            var deviceGuid = DeriveGuid(devIdSeed);

            // Alias key (will change on firmware update - i.e. when FWID changes)
            var aliasKey = DeriveEccKey(aliasSeed);

            // If the device or alias cert subjects contain the string "guid" replace with the per-device
            // GUID just calculated
            if (rAliasCertSubject.ToString().Contains("guid"))
            {
                rAliasCertSubject = new X509Name(rAliasCertSubject.ToString().Replace("guid", deviceGuid.ToString()));
            }

            if (rDeviceCertSubject.ToString().Contains("guid"))
            {
                rDeviceCertSubject = new X509Name(rDeviceCertSubject.ToString().Replace("guid", deviceGuid.ToString()));
            }

            // Create the self-signed root CA certificate
            X509Certificate rootCert = CreateRootCert(rootKey, rootSeed);

            // Create the DeviceID certificate signed by the root vendor CA
            X509Certificate devCert = CreateDeviceCert(rootKey, deviceID.Public, rootSeed);

            // Create the self-signed DeviceID certificate
            X509Certificate devCertSelfSigned = CreateSelfSignedDeviceCert(deviceID, devIdSeed);

            // Create the Alias Key certificate signed by the deviceID key
            X509Certificate aliasCert = CreateAliasCert(deviceID, aliasKey, fwid, devIdSeed);

            // Create a PKCS10 Certificate Signing Request (CSR) for the deviceId
            var deviceIdCsr = CreateCsr(deviceID, devIdSeed);

            // Create return structure containing the keys and certificates just created
            authBundle.RootCredential = new CredentialBundle
            {
                PubKey = rootKey.Public,
                PubKeyPem = DerToPem("PUBLIC KEY", rootKey.Public),
                PrivKey = rootKey.Private,
                Cert = rootCert,
                CertPem = DerToPem("CERTIFICATE", rootCert)
            };
            authBundle.DeviceIDCredential = new CredentialBundle
            {
                PubKey = deviceID.Public,
                PubKeyPem = DerToPem("PUBLIC KEY", deviceID.Public),
                Cert = devCert,
                CertPem = DerToPem("CERTIFICATE", devCert)
            };
            authBundle.SelfSignedDeviceIDCredential = new CredentialBundle
            {
                PubKey = deviceID.Public,
                PubKeyPem = DerToPem("PUBLIC KEY", deviceID.Public),
                Cert = devCertSelfSigned,
                CertPem = DerToPem("CERTIFICATE", devCertSelfSigned)
            };
            authBundle.AliasCredential = new CredentialBundle
            {
                PubKey = aliasKey.Public,
                PubKeyPem = DerToPem("PUBLIC KEY", aliasKey.Public),
                PrivKey = aliasKey.Private,
                PrivKeyPem = DerToPem("PRIVATE KEY", aliasKey.Private),
                Cert = aliasCert,
                CertPem = DerToPem("CERTIFICATE", aliasCert)
            };

            authBundle.Csr = new CsrBundle
            {
                Csr = deviceIdCsr,
                CsrPem = DerToPem("NEW CERTIFICATE REQUEST", deviceIdCsr)
            };

            return authBundle;
        }

        /// <summary>
        /// The Root Certificate simulates a vendor root CA key
        /// </summary>
        /// <param name="rootKey">Certificate signing key</param>
        /// <param name="signingSeed">Seed for the signing BRBG</param>
        /// <returns>The root certificate</returns>
        private static X509Certificate CreateRootCert(AsymmetricCipherKeyPair rootKey, byte[] signingSeed)
        {
            var random = GetDrbg(signingSeed, SeedUsage.SelfSigning);

            // set standard fields in TBS structure
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(GetSerialNumber(random));
            certGen.SetIssuerDN(rRootCertSubject);
            certGen.SetSubjectDN(rRootCertSubject);
            certGen.SetNotBefore(startTime);
            certGen.SetNotAfter(endTime);
            certGen.SetPublicKey(rootKey.Public);

            // add extensions
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign));
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(rPathLenConstraint + 1));
            certGen.AddExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rootKey.Public)));

            // sign and return
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(rSigSch, rootKey.Private, random);
            var certificate = certGen.Generate(signatureFactory);
            return certificate;
        }

        /// <summary>
        /// For real deployments, a Device Cert, if present, will be created by a vendor CA.  For test development, the
        /// Device Cert, and associated keys, are derived deterministically from the subject name of the certificate.
        /// </summary>
        /// <param name="rootKey">The cert signing key</param>
        /// <param name="deviceIdKey">The key being certified</param>
        /// <param name="signingSeed">Seed for the signing BRBG</param>
        /// <returns>The device certificate</returns>
        private static X509Certificate CreateDeviceCert(AsymmetricCipherKeyPair rootKey, AsymmetricKeyParameter deviceIdKey, byte[] signingSeed)
        {
            var random = GetDrbg(signingSeed, SeedUsage.Signing);

            // set the standard fields in the TBS strucure
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(GetSerialNumber(random));
            certGen.SetIssuerDN(rRootCertSubject);
            certGen.SetSubjectDN(rDeviceCertSubject);
            certGen.SetNotBefore(startTime);
            certGen.SetNotAfter(endTime);
            certGen.SetPublicKey(deviceIdKey);

            // add the extensions
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign));
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(rPathLenConstraint));
            certGen.AddExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rootKey.Public)));
            certGen.AddExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(deviceIdKey)));

            // sign and return the device certificate
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(rSigSch, rootKey.Private, random);
            var certificate = certGen.Generate(signatureFactory);
            return certificate;
        }

        /// <summary>
        /// For real deployments, a Device Cert, if present, will be created by a vendor CA.  For test development, the
        /// Device Cert, and associated keys, are derived deterministically from the subject name of the certificate.
        /// </summary>
        /// <param name="deviceIdKey">The cert signing key</param>
        /// <param name="signingSeed">Seed for the signing BRBG</param>
        /// <returns>The self-signed DeviceID certificate</returns>
        private static X509Certificate CreateSelfSignedDeviceCert(AsymmetricCipherKeyPair deviceIdKey, byte[] signingSeed)
        {
            var random = GetDrbg(signingSeed, SeedUsage.SelfSigning);

            // set the standard fields in the TBS strucure
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(GetSerialNumber(random));
            certGen.SetIssuerDN(rDeviceCertSubject);
            certGen.SetSubjectDN(rDeviceCertSubject);
            certGen.SetNotBefore(startTime);
            certGen.SetNotAfter(endTime);
            certGen.SetPublicKey(deviceIdKey.Public);

            // add the extensions
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign));
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(rPathLenConstraint));
            certGen.AddExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(deviceIdKey.Public)));

            // sign and return the device certificate
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(rSigSch, deviceIdKey.Private, random);
            var certificate = certGen.Generate(signatureFactory);
            return certificate;
        }

        /// <summary>
        /// The Alias Certificate is a certificate over the Alias Public key (+ the RIoT attestation extension) signed by the
        /// DeviceID key.
        /// </summary>
        /// <param name="deviceID">The cert siging key</param>
        /// <param name="aliasKey">The key being certified</param>
        /// <param name="fwid">The (simulated) hash of the upper-level firmware</param>
        /// <param name="signingSeed">Seed for the signing BRBG</param>
        /// <returns>The alias certificate</returns>
        private static X509Certificate CreateAliasCert(AsymmetricCipherKeyPair deviceID, AsymmetricCipherKeyPair aliasKey, byte[] fwid, byte[] signingSeed)
        {
            var random = GetDrbg(signingSeed, SeedUsage.Signing);

            // set standard fields in TBS structure
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(GetSerialNumber(random));
            certGen.SetIssuerDN(rDeviceCertSubject);
            certGen.SetSubjectDN(rAliasCertSubject);
            certGen.SetNotBefore(startTime);
            certGen.SetNotAfter(endTime);
            certGen.SetPublicKey(aliasKey.Public);

            // add extensions
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true, ExtendedKeyUsage.GetInstance(new DerSequence(KeyPurposeID.IdKPClientAuth)));
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            var riotExtension = CreateRIoTExtension(fwid, deviceID.Public);
            certGen.AddExtension(new DerObjectIdentifier(rExtensionOID), false, riotExtension);
            certGen.AddExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(deviceID.Public)));
            certGen.AddExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(aliasKey.Public)));

            // sign and return
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(rSigSch, deviceID.Private, random);
            var certificate = certGen.Generate(signatureFactory);
            return certificate;
        }

        /// <summary>
        /// Creates a PKCS10 Certificate Signing Request (CSR) for the DeviceID key
        /// </summary>
        /// <param name="deviceID">Signing key</param>
        /// <param name="signingSeed">Seed for the signing BRBG</param>
        /// <returns>The CSR</returns>
        private static Pkcs10CertificationRequest CreateCsr(AsymmetricCipherKeyPair deviceID, byte[] signingSeed)
        {
            var random = GetDrbg(signingSeed, SeedUsage.CSR);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(rSigSch, deviceID.Private, random);

            // adapt extension request as needed
            IList oids = new ArrayList();
            IList values = new ArrayList();

            oids.Add(X509Extensions.BasicConstraints);
            values.Add(new X509Extension(true, new DerOctetString(new BasicConstraints(rPathLenConstraint))));

            oids.Add(X509Extensions.KeyUsage);
            values.Add(new X509Extension(true, new DerOctetString(new KeyUsage(KeyUsage.KeyCertSign))));
            AttributePkcs attribute = new AttributePkcs(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                new DerSet(new X509Extensions(oids, values)));

            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(
                signatureFactory,
                rDeviceCertSubject,
                deviceID.Public,
                new DerSet(attribute),
                deviceID.Private);

            return csr;
        }

        /// <summary>
        /// Used a deterministic key generation algorithm to create an ECC key from the seed provided
        /// </summary>
        /// <param name="seed">The seed</param>
        /// <returns>The ECC key pair</returns>
        private static AsymmetricCipherKeyPair DeriveEccKey(byte[] seed)
        {
            SecureRandom random = GetDrbg(seed, SeedUsage.KeyGeneration);
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, rKeyStrength);
            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var keyPair = keyPairGenerator.GenerateKeyPair();
            return keyPair;
        }

        /// <summary>
        /// Deterministically create a GUID from a seed
        /// </summary>
        /// <param name="seed">The seed</param>
        /// <returns>The ECC key pair</returns>
        private static Guid DeriveGuid(byte[] seed)
        {
            SecureRandom random = GetDrbg(seed, SeedUsage.GuidGeneration);
            byte[] guidBytes = new byte[16];
            random.NextBytes(guidBytes);
            return new Guid(guidBytes);
        }

        /// <summary>
        /// Return the hash of buf
        /// </summary>
        /// <param name="buf">Data to be hashed</param>
        /// <returns>The hash value</returns>
        private static byte[] Hash(byte[] buf)
        {
            var md = GetDigest();
            var res = new byte[md.GetDigestSize()];
            md.BlockUpdate(buf, 0, buf.Length);
            md.DoFinal(res, 0);
            return res;
        }

        /// <summary>
        /// Return the hash of the concatentation of buf1 and buf2
        /// </summary>
        /// <param name="buf1">First block to be hashed</param>
        /// <param name="buf2">Second block to be hashed</param>
        /// <returns>The hash value</returns>
        private static byte[] Hash(byte[] buf1, byte[] buf2)
        {
            var md = GetDigest();
            var res = new byte[md.GetDigestSize()];
            md.BlockUpdate(buf1, 0, buf1.Length);
            md.BlockUpdate(buf2, 0, buf2.Length);
            md.DoFinal(res, 0);
            return res;
        }

        /// <summary>
        /// Creates a DER SEQUENCE containing the RIoT extension
        /// </summary>
        /// <param name="fwid">Firmwware ID (32 bytes)</param>
        /// <param name="deviceID">The DeviceID public key</param>
        /// <returns>The DER-encoded extension</returns>
        private static DerSequence CreateRIoTExtension(byte[] fwid, AsymmetricKeyParameter deviceID)
        {
            if (fwid.Length != 32)
            {
                throw new ArgumentException("FWID is malformed");
            }

            SubjectPublicKeyInfo devicePubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(deviceID);

            /* RIoT extension
             * {
             *      {
             *          1,                      -- version number
             *          devIdPubKey,            -- DER encoded Subject Public Key
             *          {
             *              fwIdHashAlg,        -- OID of hash alg (SHA256)
             *              fwId                -- Hash value
             *          }
             *      }
             * }
             * */

            DerSequence fwidSeq = new DerSequence(new Asn1Encodable[]
                    {
                        rFwidAlg,
                        new DerOctetString(fwid)
                    });
            DerSequence encodedDICEIdentity = new DerSequence(new Asn1Encodable[]
                    {
                        new DerInteger(1),
                        devicePubInfo,
                        fwidSeq
                    });

            return encodedDICEIdentity;
        }

        /// <summary>
        /// Converts a PEM-encodable object into a string with the header provided "PUBLIC KEY", "CERTIFICATE", etc.
        /// </summary>
        /// <param name="header">PEM header</param>
        /// <param name="obj">Object to be PEM encoded (only some objects are encodable)</param>
        /// <returns>PEM encoded object</returns>
        private static string DerToPem(string header, object obj)
        {
            var stream = new StringWriter();
            Org.BouncyCastle.OpenSsl.PemWriter writer = new Org.BouncyCastle.OpenSsl.PemWriter(stream);
            writer.WriteObject(obj);
            writer.Writer.Flush();
            return stream.ToString();
        }

        /// <summary>
        /// Hex string to byte array
        /// </summary>
        /// <param name="s">Hex string</param>
        /// <returns>Binary array</returns>
        private static byte[] HexToByteArray(string s)
        {
            int len = s.Length;
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
            {
                data[i / 2] = (byte)((Convert.ToInt32(s.Substring(i, 1), 16) << 4) + Convert.ToInt32(s.Substring(i + 1, 1), 16));
            }

            return data;
        }

        /// <summary>
        /// Creates a deterministic "random number" generator.  SeedUsage ensures that the same
        /// DRBG is not used for different purposes
        /// </summary>
        /// <param name="seed">Seed for the DRNG</param>
        /// <param name="usage">additional seed data in the form of the seed usage</param>
        /// <returns>The deterministic sequence generator</returns>
        private static SecureRandom GetDrbg(byte[] seed, SeedUsage usage)
        {
            DigestRandomGenerator rg = new DigestRandomGenerator(GetDigest());
            SecureRandom random = new SecureRandom(rg);
            random.SetSeed(Hash(new byte[1] { (byte)usage }, seed));
            return random;
        }

        /// <summary>
        /// Returns a byte[8] encoding a positive integer derived from the seeded-RNG
        /// /// </summary>
        /// <param name="r">DRNG source</param>
        /// <returns>approx 8 byte positive number</returns>
        private static BigInteger GetSerialNumber(SecureRandom r)
        {
            var serialNumber = new byte[8];
            r.NextBytes(serialNumber);
            serialNumber[0] &= 0x7F;    // positive
            serialNumber[0] |= 0x01;    // leading byte not zero
            return new BigInteger(serialNumber);
        }

        /// <summary>
        /// Get a hashing engine
        /// </summary>
        /// <returns>The hash engine</returns>
        private static IDigest GetDigest()
        {
            return new Sha256Digest();
        }

        /// <summary>
        /// Containter class for keys and certificates
        /// </summary>
        public class CredentialBundle
        {
            private AsymmetricKeyParameter pubKey;
            private AsymmetricKeyParameter privKey;
            private string pubKeyPem;
            private string privKeyPem;
            private X509Certificate cert;
            private string certPem;

            /// <summary>
            /// Gets or sets bouncy Castle public key
            /// </summary>
            public AsymmetricKeyParameter PubKey { get => this.pubKey; set => this.pubKey = value; }

            /// <summary>
            /// Gets or sets the Bouncy Castle private key (may be null)
            /// </summary>
            public AsymmetricKeyParameter PrivKey { get => this.privKey; set => this.privKey = value; }

            /// <summary>
            /// Gets or sets pEM encoded public key
            /// </summary>
            public string PubKeyPem { get => this.pubKeyPem; set => this.pubKeyPem = value; }

            /// <summary>
            /// Gets or sets pEM encoded private key (may be null)
            /// </summary>
            public string PrivKeyPem { get => this.privKeyPem; set => this.privKeyPem = value; }

            /// <summary>
            /// Gets or sets pEM encoded certificate
            /// </summary>
            public X509Certificate Cert { get => this.cert; set => this.cert = value; }

            /// <summary>
            /// Gets or sets dER-encoded certificate
            /// </summary>
            public string CertPem { get => this.certPem; set => this.certPem = value; }
        }

        /// <summary>
        /// Container class for a PKCS10 Certificate Signing Request (CSR)
        /// </summary>
        public class CsrBundle
        {
            private Pkcs10CertificationRequest csr;
            private string csrPem;

            /// <summary>
            /// Gets or sets bouncy Castle PKCS10 container
            /// </summary>
            public Pkcs10CertificationRequest Csr { get => this.csr; set => this.csr = value; }

            /// <summary>
            /// Gets or sets pEM-encoded CSR
            /// </summary>
            public string CsrPem { get => this.csrPem; set => this.csrPem = value; }
        }

        /// <summary>
        /// Container for the keys and certificates created by the RIoT Emulator
        /// </summary>
        public class DeviceAuthBundle
        {
            private CredentialBundle rootCredential;
            private CredentialBundle deviceIDCredential;
            private CredentialBundle selfSignedDeviceIDCredential;
            private CredentialBundle aliasCredential;
            private CsrBundle csr;

            /// <summary>
            /// Gets or sets certificates and keys for the simulated vendor CA
            /// </summary>
            public CredentialBundle RootCredential { get => this.rootCredential; set => this.rootCredential = value; }

            /// <summary>
            /// Gets or sets certificates and keys for a simulated vendor-signed DeviceID key
            /// </summary>
            public CredentialBundle DeviceIDCredential { get => this.deviceIDCredential; set => this.deviceIDCredential = value; }

            /// <summary>
            /// Gets or sets certificates and keys for a self-certified (non-vendor-certified) DeviceID key
            /// </summary>
            public CredentialBundle SelfSignedDeviceIDCredential { get => this.selfSignedDeviceIDCredential; set => this.selfSignedDeviceIDCredential = value; }

            /// <summary>
            /// Gets or sets certificates and keys for the Alias credential (for us in TLS client auth)
            /// </summary>
            public CredentialBundle AliasCredential { get => this.aliasCredential; set => this.aliasCredential = value; }

            /// <summary>
            /// Gets or sets pKCS10 Certificate signing request
            /// </summary>
            public CsrBundle Csr { get => this.csr; set => this.csr = value; }
        }

        /// <summary>
        /// The DICE class is used to emulate DICE-enabled hardware. It is a dependency
        /// of the RIoT emulator.The RIoT emulator is used to create keys and certificates
        /// for identification and attestation of Azure IoT devices. The emulator can be
        /// used for developing solutions on platforms that do not have DiceEmulator hardware, or
        /// can be used to create a software-only asymmetric-key based device identity (with
        /// no hardware protection for the keys).
        /// </summary>
        private class DICE
        {
            /// <summary>
            /// Simulate a DICE measurement based on a unique device secret (UDS) and the hash of the first code that
            /// is booted.
            /// </summary>
            /// <param name="uds">The seed for CDI derivation</param>
            /// <param name="codeDigest">Hash of the the first mutable code</param>
            /// <returns>The Compound Device Identity (CDI)</returns>
            public static byte[] GetCDI(byte[] uds, byte[] codeDigest)
            {
                /*
                 * This follows option (1) in
                 *      "Trusted Platform Architecture: Hardware Requirements for a Device Identifier Composition Engine"
                */
                return DICE.Hash(uds, codeDigest);
            }

            /// <summary>
            /// Hashing function for DICE emulation(SHA256)
            /// </summary>
            /// <param name="buf">Data to be hashed (on DICE hardware this woudld the first-stage boot-loader</param>
            /// <returns>Hash of buf</returns>
            private static byte[] Hash(byte[] buf)
            {
                var md = new Sha256Digest();
                var res = new byte[md.GetDigestSize()];
                md.BlockUpdate(buf, 0, buf.Length);
                md.DoFinal(res, 0);
                return res;
            }

            /// <summary>
            /// Hashing function for DICE emulation (SHA256)
            /// </summary>
            /// <param name="buf1">First buffer</param>
            /// <param name="buf2">Second Buffer</param>
            /// <returns>Hash of the concatentation of buf1 and buf2</returns>
            private static byte[] Hash(byte[] buf1, byte[] buf2)
            {
                var md = new Sha256Digest();
                var res = new byte[md.GetDigestSize()];
                md.BlockUpdate(buf1, 0, buf1.Length);
                md.BlockUpdate(buf2, 0, buf2.Length);
                md.DoFinal(res, 0);
                return res;
            }
        }
    }
}
