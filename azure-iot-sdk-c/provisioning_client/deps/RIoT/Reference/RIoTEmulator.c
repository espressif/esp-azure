/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include <stdio.h>
#include <errno.h>
#include "RIoTEmulator.h"

// Turn on debug
#define DEBUG

// Note that even though digest lengths are equivalent here, (and on most
// devices this will be the case) there is no requirement that DICE and RIoT
// use the same one-way function/digest length.
#define DICE_DIGEST_LENGTH      RIOT_DIGEST_LENGTH

// Note also that there is no requirement on the UDS length for a device.
// A 256-bit UDS is recommended but this size may vary among devices.
#define DICE_UDS_LENGTH         0x20

// We are emulating the action of a real device. Since we're not a real device
// the action of the DICE is emulated using riot crypto primitives.
#define DICE_GET_UDS_DIGEST     RiotCrypt_Hash
#define DICE_GET_CDI            RiotCrypt_Hash2

// Random (i.e., simulated) RIoT Core "measurement"
uint8_t rDigest[DICE_DIGEST_LENGTH] = {
    0xb5, 0x85, 0x94, 0x93, 0x66, 0x1e, 0x2e, 0xae,
    0x96, 0x77, 0xc5, 0x5d, 0x59, 0x0b, 0x92, 0x94,
    0xe0, 0x94, 0xab, 0xaf, 0xd7, 0x40, 0x78, 0x7e,
    0x05, 0x0d, 0xfe, 0x6d, 0x85, 0x90, 0x53, 0xa0 };

// Size, in bytes, returned when the required certificate buffer size is
// requested.  For this emulator the actual size (~552 bytes) is static,
// based on the contents of the x509TBSData struct (the fiels don't vary).
// As x509 data varies so will the overall cert length. For now, just pick
// a reasonable minimum buffer size and worry about this later.
#define REASONABLE_MIN_CERT_SIZE    DER_MAX_TBS

// The static data fields that make up the Alias Cert "to be signed" region.
// If the device SubjectCommon is *, then a device-unique GUID is generated.
// If a self-signed DeviceID cert is selected, then the tbs subject is also
// used for the issuer.
RIOT_X509_TBS_DATA x509AliasTBSData = { { 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
                                       "RIoT Core", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "*", "MSR_TEST", "US" };

// The static data fields that make up the DeviceID Cert "to be signed" region
RIOT_X509_TBS_DATA x509DeviceTBSData = { { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 },
                                       "RIoT R00t", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT Core", "MSR_TEST", "US" };

// The static data fields that make up the "root signer" Cert
RIOT_X509_TBS_DATA x509RootTBSData   = { { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E , 0x6F, 0x70, 0x81 },
                                       "RIoT R00t", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT R00t", "MSR_TEST", "US" };

// Selectors for DeviceID cert handling.
#define RIOT_ROOT_SIGNED    0x00
#define RIOT_SELF_SIGNED    0x01
#define RIOT_CSR            0x02

// DeviceID cert type (root signed, defualt)
#define DEVICE_ID_CERT_TYPE RIOT_ROOT_SIGNED

// Labels for riot key types
#define RIOT_LABEL_IDENTITY "IDENTITY"
#define RIOT_LABEL_ALIAS    "ALIASKEY"
// Macro for label sizes (skip strlen()).
#define lblSize(a)          (sizeof(a) - 1)

// Simulated "root" signing keypair
RIOT_ECC_PUBLIC  eccRootPub;
RIOT_ECC_PRIVATE eccRootPriv;

// Sets tbsData->SerialNumber to a pseudo-random value derived from seedData
static void SetSerialNumber(RIOT_X509_TBS_DATA* tbsData, const uint8_t* seedData, size_t seedLen);

// Used to populate "root" signing keypair
static void GetRootKey(RIOT_ECC_PUBLIC *Pub, RIOT_ECC_PRIVATE *Priv);

int
CreateDeviceAuthBundle(
    uint8_t     *Seed,
    uint32_t     SeedSize,
    uint8_t     *Fwid,
    uint32_t     FwidSize,
    uint8_t     *DeviceIDPublicEncoded,
    uint32_t    *DeviceIDPublicEncodedSize,
    uint8_t     *DeviceCertBuffer,
    uint32_t    *DeviceCertBufSize,
    uint32_t     DeviceCertType,
    uint8_t     *AliasKeyEncoded,
    uint32_t    *AliasKeyEncodedSize,
    uint8_t     *AliasCertBuffer,
    uint32_t    *AliasCertBufSize
);

#ifdef DEBUG
void WriteTextFile(const char* fileName, uint8_t* buf, int bufLen, uint8_t append);
void WriteBinaryFile(const char* fileName, uint8_t* buf, int bufLen);
void HexConvert(uint8_t* in, int inLen, char* outBuf, int outLen);
void PrintHex(uint8_t* buf, int bufLen);
#endif

int
main()
{
    uint8_t UDS[DICE_UDS_LENGTH]     = { 0 };
    uint8_t FWID[RIOT_DIGEST_LENGTH] = { 0 };
    uint8_t deviceIDPub[DER_MAX_PEM] = { 0 };
    uint8_t devCert[DER_MAX_PEM]     = { 0 };
    uint8_t aliasKey[DER_MAX_PEM]    = { 0 };
    uint8_t aliasCert[DER_MAX_PEM]   = { 0 };

    uint32_t deviceIDPubSize = DER_MAX_PEM;
    uint32_t aliaskeySize    = DER_MAX_PEM;
    uint32_t devCertSize     = DER_MAX_PEM;
    uint32_t aliasCertSize   = DER_MAX_PEM;

    // Go
    CreateDeviceAuthBundle(UDS, DICE_UDS_LENGTH,
                           FWID, RIOT_DIGEST_LENGTH,
                           deviceIDPub, &deviceIDPubSize,
                           devCert, &devCertSize, DEVICE_ID_CERT_TYPE,
                           aliasKey, &aliaskeySize,
                           aliasCert, &aliasCertSize);
    return 0;
}

int
CreateDeviceAuthBundle(
    uint8_t     *Seed,
    uint32_t     SeedSize,
    uint8_t     *Fwid,
    uint32_t     FwidSize,
    uint8_t     *DeviceIDPublicEncoded,
    uint32_t    *DeviceIDPublicEncodedSize,
    uint8_t     *DeviceCertBuffer,
    uint32_t    *DeviceCertBufSize,
    uint32_t     DeviceCertType, // RIOT_ROOT_SIGNED, RIOT_SELF_SIGNED, or RIOT_CSR
    uint8_t     *AliasKeyEncoded,
    uint32_t    *AliasKeyEncodedSize,
    uint8_t     *AliasCertBuffer,
    uint32_t    *AliasCertBufSize
)
{
    char                PEM[DER_MAX_PEM] = { 0 };
    uint8_t             derBuffer[DER_MAX_TBS] = { 0 };
    uint8_t             digest[DICE_DIGEST_LENGTH] = { 0 };
    uint8_t             CDI[DICE_DIGEST_LENGTH] = { 0 };
    RIOT_ECC_PUBLIC     deviceIDPub = { 0 };
    RIOT_ECC_PRIVATE    deviceIDPriv = { 0 };
    RIOT_ECC_PUBLIC     aliasKeyPub = { 0 };
    RIOT_ECC_PRIVATE    aliasKeyPriv = { 0 };
    RIOT_ECC_SIGNATURE  tbsSig = { 0 };
    DERBuilderContext   derCtx = { 0 };
    uint32_t            length = 0;

    // REVISIT: Implement "required size" invocation for this function?

    // Up-front parameter validation
    if (!(Seed) || (SeedSize != DICE_UDS_LENGTH) ||
        !(Fwid) || (FwidSize != RIOT_DIGEST_LENGTH)) {
        return -1;
    }

//----[Emulated DICE]------------------------------------------

    // Don't use UDS directly
    DICE_GET_UDS_DIGEST(digest, DICE_DIGEST_LENGTH, Seed, DICE_UDS_LENGTH);

    // Derive CDI based on UDS and RIoT Core "measurement"
    DICE_GET_CDI(CDI, DICE_DIGEST_LENGTH, digest, DICE_DIGEST_LENGTH, rDigest, DICE_DIGEST_LENGTH);

//----[Emulated layer 0 (RIoT Core)]---------------------------

    // Don't use CDI directly
    RiotCrypt_Hash(digest, RIOT_DIGEST_LENGTH, CDI, DICE_DIGEST_LENGTH);

    // Derive DeviceID key pair from CDI
    RiotCrypt_DeriveEccKey(&deviceIDPub, &deviceIDPriv,
                           digest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_IDENTITY,
                           lblSize(RIOT_LABEL_IDENTITY));

    // Set the serial number in DeviceID cert TBS region
    SetSerialNumber(&x509DeviceTBSData, digest, RIOT_DIGEST_LENGTH);

    // Combine CDI and FWID, result in digest
    RiotCrypt_Hash2(digest, RIOT_DIGEST_LENGTH,
                    digest, RIOT_DIGEST_LENGTH,
                    Fwid, RIOT_DIGEST_LENGTH);

    // Derive Alias key pair from CDI and FWID
    RiotCrypt_DeriveEccKey(&aliasKeyPub, &aliasKeyPriv,
                           digest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_ALIAS,
                           lblSize(RIOT_LABEL_ALIAS));

    // With the Alias Key pair derived, we can now Seed DRBG
    RiotCrypt_SeedDRBG((uint8_t*)&aliasKeyPriv, sizeof(RIOT_ECC_PRIVATE), NULL, 0);

    // Set the serial number in the Alias cert TBS region
    SetSerialNumber(&x509AliasTBSData, digest, RIOT_DIGEST_LENGTH);

    // Copy DeviceID Public
    length = sizeof(PEM);
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetDEREccPub(&derCtx, deviceIDPub);
    DERtoPEM(&derCtx, PUBLICKEY_TYPE, PEM, &length);
    *DeviceIDPublicEncodedSize = length;
    memcpy(DeviceIDPublicEncoded, PEM, length);

#ifdef DEBUG
    printf("DevID Public");
    PrintHex(derCtx.Buffer, derCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("DeviceIDPublic.der", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("DeviceIDPublic.pem", (uint8_t *)PEM, length);
#endif

    // Copy Alias Key Pair
    length = sizeof(PEM);
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetDEREcc(&derCtx, aliasKeyPub, aliasKeyPriv);
    DERtoPEM(&derCtx, ECC_PRIVATEKEY_TYPE, PEM, &length);
    *AliasKeyEncodedSize = length;
    memcpy(AliasKeyEncoded, PEM, length);

#ifdef DEBUG
    printf("Alias Key");
    PrintHex(derCtx.Buffer, derCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("AliasKey.der", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("AliasKey.pem", (uint8_t *)PEM, length);
#endif 

    // Build the TBS (to be signed) region of Alias Key Certificate
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetAliasCertTBS(&derCtx, &x509AliasTBSData,
                        &aliasKeyPub, &deviceIDPub,
                        Fwid, RIOT_DIGEST_LENGTH);

    // Sign the Alias Key Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

    // Generate Alias Key Certificate
    X509MakeAliasCert(&derCtx, &tbsSig);
    length = sizeof(PEM);
    DERtoPEM(&derCtx, CERT_TYPE, PEM, &length);
    *AliasCertBufSize = length;
    memcpy(AliasCertBuffer, PEM, length);

#ifdef DEBUG
    printf("Alias Cert");
    PrintHex(derCtx.Buffer, derCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("AliasCert.der", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("AliasCert.pem", (uint8_t *)PEM, length);
#endif

    // This reference supports generation of either: a "root"-signed DeviceID
    // certificate, or a certificate signing request for the DeviceID Key. 
    // In a production device, Alias Key Certificates are normally leaf certs
    // that chain back to a known root CA. This is difficult to represent in
    // simulation since different vendors each have different manufacturing 
    // processes and CAs.
    if (DeviceCertType == RIOT_SELF_SIGNED) {
        // Generating self-signed DeviceID certificate
        x509DeviceTBSData.IssuerCommon = x509DeviceTBSData.SubjectCommon;
        x509DeviceTBSData.IssuerOrg = x509DeviceTBSData.IssuerOrg;
        x509DeviceTBSData.IssuerCountry = x509DeviceTBSData.SubjectCountry;
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &deviceIDPub, NULL, 0);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
    }
    else if (DeviceCertType == RIOT_CSR) {
        // Generating CSR
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDERCsrTbs(&derCtx, &x509AliasTBSData, &deviceIDPub);

        // Sign the Alias Key Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Create CSR for DeviceID
        X509GetDERCsr(&derCtx, &tbsSig);
    }
    else {
        // Generating "root"-signed DeviceID certificate. Note, the length of
        // rootPubBuffer is determined by the max expected length in bytes
        // of an ecp coordinate (2 * COORDMAX) plus the leading '0x04' byte.
        uint8_t rootPubBuffer[(RIOT_COORDMAX * 2 + 1)];
        uint32_t rootPubBufLen = (RIOT_COORDMAX * 2 + 1);

        // Get "root" signing key
        GetRootKey(&eccRootPub, &eccRootPriv);

        // Export "root" key bytes and prepare device cert
        RiotCrypt_ExportEccPub(&eccRootPub, rootPubBuffer, &rootPubBufLen);
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &deviceIDPub, rootPubBuffer, rootPubBufLen);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &eccRootPriv);

        // Sanity check signature
        RiotCrypt_Verify(derCtx.Buffer, derCtx.Position, &tbsSig, &eccRootPub);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
    }

    // Copy DeviceID Certificate or CSR. Note, depending on DeviceCertType this 
    // may be self-signed, root-signed, or a CSR
    uint32_t pemType = CERT_TYPE;
    if (DeviceCertType == RIOT_CSR)
    {
        pemType = CERT_REQ_TYPE;
    }
    length = sizeof(PEM);
    DERtoPEM(&derCtx, pemType, PEM, &length);
    *DeviceCertBufSize = length;
    memcpy(DeviceCertBuffer, PEM, length);

#ifdef DEBUG
    printf("DeviceID Cert");
    PrintHex(derCtx.Buffer, derCtx.Position);
    PEM[length] = '\0'; // JUST FOR PRINTF
    printf("%s", PEM);
    WriteBinaryFile("DeviceIDCrt.der", derCtx.Buffer, derCtx.Position);
    WriteBinaryFile("DeviceIDCrt.pem", (uint8_t *)PEM, length);
#endif

    // If necessary, generate "root" CA cert
    if (DeviceCertType == RIOT_ROOT_SIGNED)
    {
        // Generate "root" CA certficiate
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetRootCertTBS(&derCtx, &x509RootTBSData, &eccRootPub);

        // Self-sign the "root" Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &eccRootPriv);

        // Generate "root" CA cert
        X509MakeRootCert(&derCtx, &tbsSig);

        // Copy "root" CA Certificate
        length = sizeof(PEM);
        DERtoPEM(&derCtx, CERT_TYPE, PEM, &length);

#ifdef DEBUG
        printf("\"root\" CA Cert");
        PrintHex(derCtx.Buffer, derCtx.Position);
        PEM[length] = '\0'; // JUST FOR PRINTF
        printf("%s", PEM);
        WriteBinaryFile("R00tCrt.der", derCtx.Buffer, derCtx.Position);
        WriteBinaryFile("R00tCrt.pem", (uint8_t *)PEM, length);
#endif
    }

    return 0;
}

static void SetSerialNumber(RIOT_X509_TBS_DATA* tbsData, const uint8_t* seedData, size_t seedLen)
{
    // Set the tbsData serial number to 8 bytes of data derived from seedData
    uint8_t digest[RIOT_DIGEST_LENGTH];

    // SHA-1 hash of "DICE SEED" == 6e785006 84941d8f 7880520c 60b8c7e4 3f1a3c00
    uint8_t seedExtender[20] = { 
        0x6e, 0x78, 0x50, 0x06, 0x84, 0x94, 0x1d, 0x8f, 0x78, 0x80,
        0x52, 0x0c, 0x60, 0xb8, 0xc7, 0xe4, 0x3f, 0x1a, 0x3c, 0x00};

    // Produce bytes for serial number
    RiotCrypt_Hash2(digest, sizeof(digest), seedData, seedLen, seedExtender, sizeof(seedExtender));

    // Take first 8 bytes to form serial number
    memcpy(tbsData->SerialNum, digest, RIOT_X509_SNUM_LEN);

    // DER encoded serial number must be positive and the first byte must not be zero
    tbsData->SerialNum[0] &= (uint8_t)0x7f;
    tbsData->SerialNum[0] |= (uint8_t)0x01;
    return;
}

static void GetRootKey(RIOT_ECC_PUBLIC *Pub, RIOT_ECC_PRIVATE *Priv)
{
    // The "root" signing key. This is intended for development purposes only.
    // This key is used to sign the DeviceID certificate, the certificiate for
    // this "root" key represents the "trusted" CA for the developer-mode DPS
    // server(s). Again, this is for development purposes only and (obviously)
    // provides no meaningful security whatsoever.
    uint8_t rootX[RIOT_COORDMAX] = { 
        0x68, 0xF1, 0x0D, 0x9A, 0xEF, 0x2C, 0x02, 0xF9,
        0x3D, 0x6F, 0x82, 0xB4, 0x34, 0x07, 0x1C, 0x17,
        0xD5, 0x2C, 0x75, 0xE4, 0x3C, 0x4D, 0x18, 0x10,
        0x10, 0xDC, 0x4B, 0x2B, 0x33, 0x48, 0x2D, 0x80 };
    uint8_t rootY[RIOT_COORDMAX] = {
        0x9A, 0x5F, 0x2B, 0x3D, 0xF4, 0x2E, 0xA1, 0xE1,
        0x5D, 0xD3, 0x66, 0xCA, 0xB5, 0x99, 0x09, 0x58,
        0x99, 0x8B, 0x68, 0x79, 0xFA, 0xBC, 0xC9, 0x84,
        0xDD, 0x30, 0x23, 0xFC, 0x08, 0xB5, 0x78, 0xF2 };
    uint8_t rootD[RIOT_COORDMAX]  = {
        0xF3, 0x0F, 0x86, 0x2B, 0x66, 0xAD, 0x64, 0xF3,
        0x40, 0x29, 0x39, 0xC1, 0x11, 0x7C, 0x31, 0xCB,
        0x56, 0x19, 0xE6, 0x3E, 0xAE, 0x11, 0xF2, 0xE1,
        0x1E, 0xC1, 0x19, 0x9D, 0x90, 0x7F, 0x04, 0x23 };

    // Emulator-only: We need to populate the root key.
    // Note that the following 'memset's are unnecessry in this simulated
    // environment but on a real device it is good to stay in the habit of
    // clearing potentially sensative data when it is no longer needed.
    mbedtls_mpi_read_binary(&Pub->X, rootX, RIOT_COORDMAX);
    memset(rootX, 0, sizeof(rootX));
    mbedtls_mpi_read_binary(&Pub->Y, rootY, RIOT_COORDMAX);
    memset(rootY, 0, sizeof(rootY));
    mbedtls_mpi_lset(&Pub->Z, 1);
    mbedtls_mpi_read_binary(Priv,  rootD, RIOT_COORDMAX);
    memset(rootD, 0, sizeof(rootD));
    return;
}

#ifdef DEBUG
// What follows are some helper routines used for debugging.
void HexConvert(uint8_t* in, int inLen, char* outBuf, int outLen)
{
    int err, pos = 0;
    for (int j = 0; j < inLen; j++)
    {
        err = snprintf(outBuf + pos, outLen - j * 2, "%02X", in[j]);
        if (err == -1) return;
        pos += 2;
    }
    return;
}
void PrintHex(uint8_t* buf, int bufLen)
{
    printf("\n");
    for (int j = 0; j < bufLen; j++)
        printf("%02x", buf[j]);
    printf("\n");
    return;
}
void WriteBinaryFile(const char* fileName, uint8_t* buf, int bufLen)
{
    FILE* f;
    f = fopen(fileName, "wb");
    if (f == NULL) return;
    int len = (int)fwrite(buf, 1, bufLen, f);
    if (len != bufLen) return;
    int res = fclose(f);
    if (res != 0) return;
    return;
}
void WriteTextFile(const char* fileName, uint8_t* buf, int bufLen, uint8_t append)
{
    FILE* f;
    char* mode = append ? "a+t" : "wt";
    f = fopen(fileName, mode);
    if (f == NULL) return;
    int len = (int)fwrite(buf, 1, bufLen, f);
    if (len != bufLen) return;
    int res = fclose(f);
    if (res != 0) return;
    return;
}
#endif