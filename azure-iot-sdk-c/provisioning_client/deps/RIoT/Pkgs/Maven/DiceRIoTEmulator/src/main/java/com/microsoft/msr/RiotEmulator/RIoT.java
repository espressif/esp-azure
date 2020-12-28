/*
 *
 *  Copyright (c) Microsoft. All rights reserved.
 *  Licensed under the MIT license. See LICENSE file in the project root for full license information.
 *
 */
package com.microsoft.msr.RiotEmulator;

import com.microsoft.msr.DiceEmulator.DICE;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;

public class RIoT {

    // Algs/Crypto parameters

    /**
     * The RIoT Emulator DRBG
     */
    private static String rDRBG = "SHA1PRNG";

    /**
     * The ECC curve to use (NIST P-256)
     */
    private static String rEcCurve = "P-256";

    /**
     * The signing algorithm to use
     */
    private static String rSignAlg = "ECDSA";

    /**
     * The signature scheme
     */
    private static String rSigSch = "SHA256withECDSA";

    /**
     * The full signature scheme
     */
    private static ASN1ObjectIdentifier rSignatureOID = X9ObjectIdentifiers.ecdsa_with_SHA256;

    // Simulated input(s)

    /**
     * Simulated RIoT Core "measurement"
     */
    private static byte[] rDigest = hstoba("b5859493661e2eae9677c55d590b9294e094abafd740787e050dfe6d859053a0");

    /**
     * Seed for deterministic (and simulated) "root" CA signing key pair
     */
    private static byte[] rR00t = hstoba("e3e7c713573fd9c8b8e1eaf453f1561502f071c05349c8dae626a90b1788e570");

    // Certificates

    /**
     * Serial number for DeviceID Certificate
     */
    private static byte[] rDevCertSerial = hstoba("0e0d0c0b0a");

    /**
     * Serial number for DeviceID Certificate
     */
    private static byte[] rAlisCertSerial = hstoba("0a0b0c0d0e");

    // TODO: Create a container class for certificate info (and use one per cert)
    private static String rRootCertIssuerName = "RIoT R00t";
    private static String rRootCertIssuerOrg = "MSR_TEST";
    private static String rRootCertIssuerCountry = "US";
    private static String rRootCertSubjectName = rRootCertIssuerName;       // Self-signed
    private static String rRootCertSubjectOrg = rRootCertIssuerOrg;         // Self-signed
    private static String rRootCertSubjectCountry = rRootCertIssuerCountry; // Self-signed

    private static String rDeviceCertIssuerName = rRootCertSubjectName;
    private static String rDeviceCertIssuerOrg = rRootCertSubjectOrg;
    private static String rDeviceCertIssuerCountry = rRootCertSubjectCountry;
    private static String rDeviceCertSubjectName = "RIoT Core";
    private static String rDeviceCertSubjectOrg = "MSR_TEST";
    private static String rDeviceCertSubjectCountry = "US";

    private static String rAliasCertIssuerName = rDeviceCertSubjectName;
    private static String rAliasCertIssuerOrg = rDeviceCertSubjectOrg;
    private static String rAliasCertIssuerCountry = rDeviceCertSubjectCountry;
    private static String rAliasCertSubjectName = "RIoT Device";
    private static String rAliasCertSubjectOrg = "MSR_TEST";
    private static String rAliasCertSubjectCountry = "US";

    /**
     * The OID for the DICE extension that encodes the DeviceID and FWID
     */
    private static String rExtensionOID = "2.23.133.5.4.1";

    /**
     * The path length constraint for the self-signed DeviceID certificate
     */
    private static int rPathLenConstraint = 1;

    /**
     * Certificate validity period (start)
     */
    private static String rValidityStart = "20170101000000 GMT";

    /**
     * Certificate validity period (end)
     */
    private static String rValidityEnd = "37011231235959 GMT";

    // Public

    /**
     * Container for PEM-encoded keys and certificates created by the RIoT Emulator
     */
    public static class DeviceAuthBundle {
        /**
         * Public portion of the "root" CA Key
         */
        public PublicKey RootPublicKey;
        /**
         * PEM-encoded public portion of the "root" CA Key
         */
        public String RootPublicKeyPem;
        /**
         * Private portion of the "root" CA Key
         */
        public PrivateKey RootPrivateKey;
        /**
         * PEM-encoded private portion of the "root" CA Key
         */
        public String RootPrivateKeyPem;
        /**
         * Self-signed "root" certificate
         */
        public X509Certificate RootCert;
        /**
         * PEM-encoded self-signed "root" certificate
         */
        public String RootCertPem;
        /**
         * Public portion of the DeviceID key
         */
        public PublicKey DeviceIDPublic;
        /**
         * PEM-encoded public DeviceID key
         */
        public String DeviceIDPublicPem;
        /**
         * Self-signed DeviceID certificate
         */
        public X509Certificate DeviceIDCert;
        /**
         * PEM-encoded self-signed DeviceID certificate
         */
        public String DeviceIDCertPem;
        /**
         * PEM-encoded self-signed Certificate Signing Request (CSR) for the
         * DeviceID (may be used to obtain a certificate from the device vendor PKI)
         */
        public String DeviceIDCSR;
        /**
         * Public portion of the Alias Key
         */
        public PublicKey AliasPublicKey;
        /**
         * PEM-encoded public portion of the Alias Key
         */
        public String AliasPublicKeyPem;
        /**
         * Private portion of the Alias Key
         */
        public PrivateKey AliasPrivateKey;
        /**
         * PEM-encoded private portion of the Alias Key
         */
        public String AliasPrivateKeyPem;
        /**
         * Certificate signed by the DeviceID key encoding the public DeviceID and the FWID
         */
        public X509Certificate AliasCert;
        /**
         * PEM-encoded certificate signed by the DeviceID key encoding the public
         * DeviceID and the FWID
         */
        public String AliasCertPem;
        /**
         * Certificate signed by the "root" key for "proof of posession"
         */
        public X509Certificate LeafCert;
        /**
         * PEM-encoded certificate signed signed by the "root" key for "proof of posession"
         */
        public String LeafCertPem;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Create a certificate proving possession of the root key.
     *
     * @param devAuth       An initialized DeviceAuthBundle containing DICE/RIoT keys and certs
     * @param commonName    The "verifier" string from the DPS to be inserted in the cert's TBS data
     */
    public static void CreateLeafCert(DeviceAuthBundle devAuth, String commonName)
    {
        try {
            devAuth.LeafCert = RIoT.makeDeviceCert(devAuth, commonName);
            devAuth.LeafCertPem = dertopem("CERTIFICATE", devAuth.LeafCert.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        return;
    }

    /**
     * The RIoT Emulator.  This takes a UDS value and a FWID and creates the resultant DeviceID and Alias
     * Keys and Certificates.
     *
     * @param UDS       The Unique Device Secret for this emulated "device"
     * @param FWID      The Firmware ID (e.g., the measurement of the firmware image) on this emulated "device"
     * @param createCSR Indicates whether a Certificate Signing Request should be generated
     * @param rCN       String to provide as Subject Common Name in "root" CA Key Certificate
     * @param dCN       String to provide as Subject Common Name in DeviceID Key Certificate
     * @param aCN       String to provide as Subject Common Name in Alias Key Certificate
     * @return An instance of DeviceAuthBundle containing DeviceID and Alias Keys and Certificates
     */
    public static DeviceAuthBundle CreateDeviceAuthBundle(byte[] UDS, byte[] FWID, boolean createCSR,
                                                          String rCN, String dCN, String aCN) {
        rRootCertSubjectName = rRootCertIssuerName = rDeviceCertIssuerName = rCN;   // Self-signed
        rDeviceCertSubjectName = rAliasCertIssuerName = dCN;
        rAliasCertSubjectName = aCN;
        return CreateDeviceAuthBundle(UDS, FWID, createCSR);
    }

    /**
     * The RIoT Emulator.  This takes a UDS value and a FWID and creates the resultant DeviceID and Alias
     * Keys and Certificates.
     *
     * @param UDS       The Unique Device Secret for this emulated "device"
     * @param FWID      The Firmware ID (e.g., the measurement of the firmware image) on this emulated "device"
     * @param createCSR Indicates whether a Certificate Signing Request should be generated
     * @return An instance of DeviceAuthBundle containing DeviceID and Alias Keys and Certificates
     */
    public static DeviceAuthBundle CreateDeviceAuthBundle(byte[] UDS, byte[] FWID, boolean createCSR) {
        if ((UDS.length != 32) || (FWID.length != 32)) {
            throw new IllegalArgumentException("UDS and FWID must be 32-bytes in length");
        }
        try {
            DeviceAuthBundle authBundle = new DeviceAuthBundle();

            /* Don't use UDS directly */
            byte[] digest = DICE.DiceSHA256(UDS);

            /* Derive CDI based on UDS and RIoT Core "measurement" */
            byte[] CDI = DICE.DiceSHA256(digest, rDigest);

            /* Don't use CDI directly */
            digest = RIoT.Hash(CDI);

            /* Derive deterministic "root" CA key pair */
            KeyPair rootKey = RIoT.DeriveEccKey(rR00t);

            /* Derive DeviceID key pair from CDI */
            KeyPair devID = RIoT.DeriveEccKey(digest);

            /* Combine CDI and FWID, result in digest */
            digest = RIoT.Hash(digest, FWID);

            /* Derive Alias Key pair from CDI and FWID */
            KeyPair aliasKey = RIoT.DeriveEccKey(digest);

            /* Done with keys */
            authBundle.RootPublicKey = rootKey.getPublic();
            authBundle.RootPublicKeyPem = dertopem("PUBLIC KEY", rootKey.getPublic().getEncoded());

            authBundle.RootPrivateKey = rootKey.getPrivate();
            authBundle.RootPrivateKeyPem = dertopem("PRIVATE KEY", rootKey.getPrivate().getEncoded());

            authBundle.DeviceIDPublic = devID.getPublic();
            authBundle.DeviceIDPublicPem = dertopem("PUBLIC KEY", devID.getPublic().getEncoded());

            authBundle.AliasPublicKey = aliasKey.getPublic();
            authBundle.AliasPublicKeyPem = dertopem("PUBLIC KEY", aliasKey.getPublic().getEncoded());

            authBundle.AliasPrivateKey = aliasKey.getPrivate();
            authBundle.AliasPrivateKeyPem = dertopem("PRIVATE KEY", aliasKey.getPrivate().getEncoded());

            /* Create the "root" CA certificate */
            X509Certificate rootCert = RIoT.makeRootCert(rootKey);

            /* Create the DeviceID certificate */
            X509Certificate devCert = RIoT.makeDeviceCert(rootKey, devID);

            /* Create the Alias Key certificate */
            X509Certificate aliasCert = RIoT.makeAliasCert(devID, aliasKey, FWID);

            /* Done with Certificates */
            authBundle.RootCert = rootCert;
            authBundle.RootCertPem = dertopem("CERTIFICATE", rootCert.getEncoded());

            authBundle.DeviceIDCert = devCert;
            authBundle.DeviceIDCertPem = dertopem("CERTIFICATE", devCert.getEncoded());

            authBundle.AliasCert = aliasCert;
            authBundle.AliasCertPem = dertopem("CERTIFICATE", aliasCert.getEncoded());

            return authBundle;

        } catch (Exception e) {

            e.printStackTrace();
            return null;
        }
    }

    private static X509Certificate makeRootCert(KeyPair rootKey)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ParseException, SignatureException, CertificateException {

    SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(rootKey.getPublic().getEncoded());

    X500NameBuilder issBldr = new X500NameBuilder(BCStyle.INSTANCE);
        issBldr.addRDN(BCStyle.CN,rRootCertIssuerName);
        issBldr.addRDN(BCStyle.O,rRootCertIssuerOrg);
        issBldr.addRDN(BCStyle.C,rRootCertIssuerCountry);
    X500Name issuer = issBldr.build();

    X500NameBuilder subBldr = new X500NameBuilder(BCStyle.INSTANCE);
        subBldr.addRDN(BCStyle.CN,rRootCertSubjectName);
        subBldr.addRDN(BCStyle.O,rRootCertSubjectOrg);
        subBldr.addRDN(BCStyle.C,rRootCertSubjectCountry);
    X500Name subject = subBldr.build();

    Signature sig = Signature.getInstance(rSigSch, BouncyCastleProvider.PROVIDER_NAME);
    SecureRandom seed = SecureRandom.getInstance(rDRBG);
    seed.setSeed(RIoT.Hash(rR00t)); // Deterministic seed, don't use directly
    sig.initSign(rootKey.getPrivate(), seed);

    Time vStart = new Time((new SimpleDateFormat("yyyymmddhhmmss Z")).parse(rValidityStart));
    Time vEnd = new Time((new SimpleDateFormat("yyyymmddhhmmss Z")).parse(rValidityEnd));

    V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

    /* Set certificate fields */
    certGen.setSerialNumber(new ASN1Integer(hstoba("5A4B3C2D1E")));
    certGen.setIssuer(issuer);
    certGen.setSubject(subject);
    certGen.setStartDate(vStart);
    certGen.setEndDate(vEnd);
    certGen.setSubjectPublicKeyInfo(pubKeyInfo);
    certGen.setSignature(new

    AlgorithmIdentifier(rSignatureOID));

    /* Next, create extensions */
    ExtensionsGenerator extGen = new ExtensionsGenerator();
    extGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));
    extGen.addExtension(Extension.basicConstraints,true, new BasicConstraints(rPathLenConstraint + 1));

    /* Set the extensions in the certificate */
    certGen.setExtensions(extGen.generate());

    /* Create the to-be-signed (TBS) certificate structure */
    TBSCertificate tbsCert = certGen.generateTBSCertificate();

    /* ...And sign it! (This is a self-signed cert) */
    sig.update(tbsCert.getEncoded(ASN1Encoding.DER));
    byte[] certSignature = sig.sign();

    /* The final X509 certificate is the ASN.1 vector (tbsCert, sigAlg, certSignature) */
    ASN1EncodableVector encVec = new ASN1EncodableVector();
    encVec.add(tbsCert);
    encVec.add(new

    AlgorithmIdentifier(rSignatureOID));
    encVec.add(new DERBitString(certSignature));
    byte[] certDER = new DERSequence(encVec).getEncoded(ASN1Encoding.DER);

    /* Now, finally, make the X509 cert and return */
    X509Certificate cert = (X509Certificate) CertificateFactory
            .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
            .generateCertificate(new ByteArrayInputStream(certDER));

    return cert;
}

    // Used to create the leaf "verifier" cert
    private static X509Certificate makeDeviceCert(DeviceAuthBundle devAuth, String commonName)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ParseException, SignatureException, CertificateException {

        KeyPair root = new KeyPair(devAuth.RootPublicKey, devAuth.RootPrivateKey);
        KeyPair devID = new KeyPair(devAuth.DeviceIDPublic, null);
        return makeDeviceCert(root, devID, commonName);
    }

    // Default Subject Common Name for DeviceID certificate
    private static X509Certificate makeDeviceCert(KeyPair rootKey, KeyPair deviceID)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ParseException, SignatureException, CertificateException {
        return makeDeviceCert(rootKey, deviceID, rDeviceCertSubjectName);
    }

    // Create the DeviceID certificate
    private static X509Certificate makeDeviceCert(KeyPair rootKey, KeyPair deviceID, String commonName)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ParseException, SignatureException, CertificateException {

        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(deviceID.getPublic().getEncoded());

        X500NameBuilder issBldr = new X500NameBuilder(BCStyle.INSTANCE);
        issBldr.addRDN(BCStyle.CN, rDeviceCertIssuerName);
        issBldr.addRDN(BCStyle.O, rDeviceCertIssuerOrg);
        issBldr.addRDN(BCStyle.C, rDeviceCertIssuerCountry);
        X500Name issuer = issBldr.build();

        X500NameBuilder subBldr = new X500NameBuilder(BCStyle.INSTANCE);
        subBldr.addRDN(BCStyle.CN, commonName);
        subBldr.addRDN(BCStyle.O, rDeviceCertSubjectOrg);
        subBldr.addRDN(BCStyle.C, rDeviceCertSubjectCountry);
        X500Name subject = subBldr.build();

        Signature sig = Signature.getInstance(rSigSch, BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom seed = SecureRandom.getInstance(rDRBG);

        seed.setSeed(RIoT.Hash(rDeviceCertSubjectName.getBytes())); // Deterministic seed, don't use directly
        sig.initSign(rootKey.getPrivate(), seed); // TODO: This needs to change, see RNG comment in C-Emulator

        Time vStart = new Time((new SimpleDateFormat("yyyymmddhhmmss Z")).parse(rValidityStart));
        Time vEnd = new Time((new SimpleDateFormat("yyyymmddhhmmss Z")).parse(rValidityEnd));

        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        /* Set certificate fields */
        certGen.setSerialNumber(new ASN1Integer(hstoba("0E0D0C0B0A")));
        certGen.setIssuer(issuer);
        certGen.setSubject(subject);
        certGen.setStartDate(vStart);
        certGen.setEndDate(vEnd);
        certGen.setSubjectPublicKeyInfo(pubKeyInfo);
        certGen.setSignature(new AlgorithmIdentifier(rSignatureOID));

        /* Next, create extensions */
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        //extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        extGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(rPathLenConstraint));

        /* Set the extensions in the certificate */
        certGen.setExtensions(extGen.generate());

        /* Create the to-be-signed (TBS) certificate structure */
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        /* ...And sign it! (This is a self-signed cert) */
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));
        byte[] certSignature = sig.sign();

        /* The final X509 certificate is the ASN.1 vector (tbsCert, sigAlg, certSignature) */
        ASN1EncodableVector encVec = new ASN1EncodableVector();
        encVec.add(tbsCert);
        encVec.add(new AlgorithmIdentifier(rSignatureOID));
        encVec.add(new DERBitString(certSignature));
        byte[] certDER = new DERSequence(encVec).getEncoded(ASN1Encoding.DER);

        /* Now, finally, make the X509 cert and return */
        X509Certificate cert = (X509Certificate) CertificateFactory
                .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(certDER));

        return cert;
    }

    private static X509Certificate makeAliasCert(KeyPair deviceID, KeyPair aliasKey, byte[] FWID)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException,
                   SignatureException, ParseException, CertificateException {
        SubjectPublicKeyInfo devicePub = SubjectPublicKeyInfo.getInstance(deviceID.getPublic().getEncoded());
        SubjectPublicKeyInfo aliasPub = SubjectPublicKeyInfo.getInstance(aliasKey.getPublic().getEncoded());

        X500NameBuilder issBldr = new X500NameBuilder(BCStyle.INSTANCE);
        issBldr.addRDN(BCStyle.CN, rAliasCertIssuerName);
        issBldr.addRDN(BCStyle.O, rAliasCertIssuerOrg);
        issBldr.addRDN(BCStyle.C, rAliasCertIssuerCountry);
        X500Name issuer = issBldr.build();

        X500NameBuilder subBldr = new X500NameBuilder(BCStyle.INSTANCE);
        subBldr.addRDN(BCStyle.CN, rAliasCertSubjectName);
        subBldr.addRDN(BCStyle.O, rAliasCertSubjectOrg);
        subBldr.addRDN(BCStyle.C, rAliasCertSubjectCountry);
        X500Name subject = subBldr.build();

        Signature sig = Signature.getInstance(rSigSch, BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom seed = SecureRandom.getInstance(rDRBG);

        seed.setSeed(RIoT.Hash(FWID)); // Deterministic seed, don't use FWID directly
        sig.initSign(deviceID.getPrivate(), seed); // TODO: This needs to change, see RNG comment in C-Emulator

        Time vStart = new Time((new SimpleDateFormat("yyyymmddhhmmss Z")).parse(rValidityStart));
        Time vEnd = new Time((new SimpleDateFormat("yyyymmddhhmmss Z")).parse(rValidityEnd));

        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        /* Set certificate fields */
        certGen.setSerialNumber(new ASN1Integer(rAlisCertSerial));
        certGen.setIssuer(issuer);
        certGen.setSubject(subject);
        certGen.setStartDate(vStart);
        certGen.setEndDate(vEnd);
        certGen.setSubjectPublicKeyInfo(aliasPub);
        certGen.setSignature(new AlgorithmIdentifier(rSignatureOID));

        /* Add the extensions */
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        /* TLS client auth */
        extGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

        /* The full DeviceID public key and the FWID are encoded as Subject Alternative Name */
        DERSequence riotExtension = getRiotExtension(FWID, deviceID);

        /* Add RIoT Extension */
        extGen.addExtension(new ASN1ObjectIdentifier(rExtensionOID), false, riotExtension);

        //// wrapping to allow this name to be encoded in the OtherName field of a SAN
        //DERTaggedObject explicitEnvelope = new DERTaggedObject(false, 0, riotExtension);
        //DERSequence retSeq = new DERSequence(explicitEnvelope);
        //
        //extGen.addExtension(Extension.subjectAlternativeName, true, retSeq);

        /* Set the extensions in the certificate */
        certGen.setExtensions(extGen.generate());

        /* Create the to-be-signed (TBS) certificate structure */
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        /* ...And sign it! */
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));
        byte[] certSignature = sig.sign();

         /* The final X509 certificate is the ASN.1 vector (tbsCert, sigAlg, certSignature) */
        ASN1EncodableVector encVec = new ASN1EncodableVector();
        encVec.add(tbsCert);
        encVec.add(new AlgorithmIdentifier(rSignatureOID));
        encVec.add(new DERBitString(certSignature));
        byte[] certDER = new DERSequence(encVec).getEncoded(ASN1Encoding.DER);

        /* Now, finally, make the X509 cert and return */
        X509Certificate cert = (X509Certificate) CertificateFactory
                .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(certDER));

        return cert;
    }

    /**
     * Create an ECC key pair deterministically based on the provided source data
     *
     * @param srcData The seed for key derivation
     * @return A new ECC key pair
     * @throws NoSuchAlgorithmException           Problem with rSignAlg
     * @throws NoSuchProviderException            Problem with BC provider
     * @throws InvalidAlgorithmParameterException Problem with rEcCurve
     */
    public static KeyPair DeriveEccKey(byte[] srcData)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(rEcCurve);
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance(rSignAlg, BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom seed = SecureRandom.getInstance(rDRBG);
        seed.setSeed(srcData); // Deterministic seed value based on srcData
        ecGen.initialize(ecGenSpec, seed);
        KeyPair eccKP = ecGen.generateKeyPair();

        return eccKP;
    }

    /**
     * Hashing function for RIoT emulation (SHA256)
     *
     * @param buf Byte buffer from which digest is computed
     * @return Digest of 'buf'
     * @throws NoSuchAlgorithmException When no "SHA-256"
     */
    public static byte[] Hash(byte[] buf)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buf);
        return md.digest();
    }

    /**
     * Hash function for DICE emulation (SHA256)
     *
     * @param buf1 First byte buffer to be included in digest
     * @param buf2 Second byte buffer to be included in digest
     * @return Digest of 'buf1' and 'buf2'
     * @throws NoSuchAlgorithmException When no "SHA-256"
     */
    public static byte[] Hash(byte[] buf1, byte[] buf2)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buf1);
        md.update(buf2);
        return md.digest();
    }

    private static DERSequence getRiotExtension(byte[] FWID, KeyPair deviceID) {
        /* The extension is constructed from the inside out */
        SubjectPublicKeyInfo devicePubInfo = SubjectPublicKeyInfo.getInstance(deviceID.getPublic().getEncoded());

        /* {hashAlgId, FWID Hash} */
        DERSequence FWIDseq = new DERSequence(new ASN1Encodable[]
                {
                        NISTObjectIdentifiers.id_sha256,
                        new DEROctetString(FWID)
                });

        /* {1, DeviceID, FWID} */
        DERSequence EncodedDICEIdentity = new DERSequence(new ASN1Encodable[]
                {
                        new ASN1Integer(1), // version
                        devicePubInfo,
                        FWIDseq
                });

        //// {riotOid, encodedIdentity}
        //DERSequence TaggedEncodedID = new DERSequence(new ASN1Encodable[]
        //        {
        //                new ASN1ObjectIdentifier(rExtensionOID),
        //                EncodedDICEIdentity
        //        });
        //
        return EncodedDICEIdentity;
    }

    /**
     * Convert DER encoded data to PEM with provided header
     * @param header The PEM header e.g., "PUBLIC KEY", "CERTIFICATE", etc.
     * @param derEncodedData DER-encoded byte array
     * @return PEM-encoded string
     * @throws IOException Error on writeObject/close
     */
    private static String dertopem(String header, byte[] derEncodedData)
            throws IOException {
        PemObject obj = new PemObject(header, derEncodedData);
        StringWriter strWri = new StringWriter();
        PemWriter pemWri = new PemWriter(strWri);

        pemWri.writeObject(obj);
        pemWri.close();

        return strWri.toString();
    }

    /**
     * Convert a hex string to an array of bytes
     * @param s Hex string to convert
     * @return Converted byte array
     */
    private static byte[] hstoba(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
