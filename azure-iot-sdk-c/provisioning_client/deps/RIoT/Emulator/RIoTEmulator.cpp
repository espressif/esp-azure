/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "stdafx.h"
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "RIoT.h"
#include "RiotCrypt.h"
#include "RiotDerEnc.h"
#include "RiotX509Bldr.h"
#include "DiceSha256.h"

//Debug
#define DEBUG

// Note that even though digest lengths are equivalent here, (and on most
// devices this will be the case) there is no requirement that DICE and RIoT
// use the same one-way function/digest length.
#define DICE_DIGEST_LENGTH  RIOT_DIGEST_LENGTH

// Note also that there is no requirement on the UDS length for a device.
// A 256-bit UDS is recommended but this size may vary among devices.
#define DICE_UDS_LENGTH     0x20

// Random (i.e., simulated) RIoT Core "measurement"
uint8_t rDigest[DICE_DIGEST_LENGTH] = {
    0xb5, 0x85, 0x94, 0x93, 0x66, 0x1e, 0x2e, 0xae,
    0x96, 0x77, 0xc5, 0x5d, 0x59, 0x0b, 0x92, 0x94,
    0xe0, 0x94, 0xab, 0xaf, 0xd7, 0x40, 0x78, 0x7e,
    0x05, 0x0d, 0xfe, 0x6d, 0x85, 0x90, 0x53, 0xa0 };

// Size, in bytes, returned when the required certificate buffer size is
// requested.  For this emulator the actual size (~552 bytes) is static,
// based on the contents of the x509TBSData struct (the fiels don't vary).
// As x509 data varies so will, obviously, the overall cert length. For now,
// just pick a reasonable minimum buffer size and worry about this later.
#define REASONABLE_MIN_CERT_SIZE    DER_MAX_TBS

// The static data fields that make up the Alias Cert "to be signed" region
RIOT_X509_TBS_DATA x509AliasTBSData = { { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E },
                                       "RIoT Core", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT Device", "MSR_TEST", "US" };

// The static data fields that make up the DeviceID Cert "to be signed" region
RIOT_X509_TBS_DATA x509DeviceTBSData = { { 0x0E, 0x0D, 0x0C, 0x0B, 0x0A },
                                       "RIoT R00t", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT Core", "MSR_TEST", "US" };

// The static data fields that make up the "root signer" Cert
RIOT_X509_TBS_DATA x509RootTBSData   = { { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E },
                                       "RIoT R00t", "MSR_TEST", "US",
                                       "170101000000Z", "370101000000Z",
                                       "RIoT R00t", "MSR_TEST", "US" };

// Selectors for DeviceID cert handling (See comment below)
#define RIOT_ROOT_SIGNED    0x00
#define RIOT_SELF_SIGNED    0x01
#define RIOT_CSR            0x02

// The "root" signing key. This is intended for development purposes only.
// This key is used to sign the DeviceID certificate, the certificiate for
// this "root" key represents the "trusted" CA for the developer-mode DPS
// server(s). Again, this is for development purposes only and (obviously)
// provides no meaningful security whatsoever.
BYTE eccRootPubBytes[sizeof(ecc_publickey)] = {
    0xeb, 0x9c, 0xfc, 0xc8, 0x49, 0x94, 0xd3, 0x50, 0xa7, 0x1f, 0x9d, 0xc5,
    0x09, 0x3d, 0xd2, 0xfe, 0xb9, 0x48, 0x97, 0xf4, 0x95, 0xa5, 0x5d, 0xec,
    0xc9, 0x0f, 0x52, 0xa1, 0x26, 0x5a, 0xab, 0x69, 0x00, 0x00, 0x00, 0x00,
    0x7d, 0xce, 0xb1, 0x62, 0x39, 0xf8, 0x3c, 0xd5, 0x9a, 0xad, 0x9e, 0x05,
    0xb1, 0x4f, 0x70, 0xa2, 0xfa, 0xd4, 0xfb, 0x04, 0xe5, 0x37, 0xd2, 0x63,
    0x9a, 0x46, 0x9e, 0xfd, 0xb0, 0x5b, 0x1e, 0xdf, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };

BYTE eccRootPrivBytes[sizeof(ecc_privatekey)] = {
    0xe3, 0xe7, 0xc7, 0x13, 0x57, 0x3f, 0xd9, 0xc8, 0xb8, 0xe1, 0xea, 0xf4,
    0x53, 0xf1, 0x56, 0x15, 0x02, 0xf0, 0x71, 0xc0, 0x53, 0x49, 0xc8, 0xda,
    0xe6, 0x26, 0xa9, 0x0b, 0x17, 0x88, 0xe5, 0x70, 0x00, 0x00, 0x00, 0x00 };

int
CreateDeviceAuthBundle(
    BYTE    *Seed,
    DWORD    SeedSize,
    BYTE    *Fwid,
    DWORD    FwidSize,
    BYTE    *DeviceIDPublicEncoded,
    DWORD   *DeviceIDPublicEncodedSize,
    BYTE    *DeviceCertBuffer,
    DWORD   *DeviceCertBufSize,
    DWORD    DeviceCertType,
    BYTE    *AliasKeyEncoded,
    DWORD   *AliasKeyEncodedSize,
    BYTE    *AliasCertBuffer,
    DWORD   *AliasCertBufSize
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
    BYTE    UDS[DICE_UDS_LENGTH]     = { 0 };
    BYTE    FWID[RIOT_DIGEST_LENGTH] = { 0 };
    BYTE    deviceIDPub[DER_MAX_PEM] = { 0 };
    BYTE    devCert[DER_MAX_PEM]     = { 0 };
    BYTE    aliasKey[DER_MAX_PEM]    = { 0 };
    BYTE    aliasCert[DER_MAX_PEM]   = { 0 };

    DWORD   deviceIDPubSize = DER_MAX_PEM;
    DWORD   aliaskeySize    = DER_MAX_PEM;
    DWORD   devCertSize     = DER_MAX_PEM;
    DWORD   aliasCertSize   = DER_MAX_PEM;

    CreateDeviceAuthBundle(UDS, DICE_UDS_LENGTH,
                           FWID, RIOT_DIGEST_LENGTH,
                           deviceIDPub, &deviceIDPubSize,
                           devCert, &devCertSize, RIOT_ROOT_SIGNED,
                           aliasKey, &aliaskeySize,
                           aliasCert, &aliasCertSize);

    return 0;
}

int
CreateDeviceAuthBundle(
    BYTE    *Seed,
    DWORD    SeedSize,
    BYTE    *Fwid,
    DWORD    FwidSize,
    BYTE    *DeviceIDPublicEncoded,
    DWORD   *DeviceIDPublicEncodedSize,
    BYTE    *DeviceCertBuffer,
    DWORD   *DeviceCertBufSize,
    DWORD    DeviceCertType, // RIOT_ROOT_SIGNED, RIOT_SELF_SIGNED, or RIOT_CSR
    BYTE    *AliasKeyEncoded,
    DWORD   *AliasKeyEncodedSize,
    BYTE    *AliasCertBuffer,
    DWORD   *AliasCertBufSize
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

    // Don't use UDS directly
    DiceSHA256(Seed, DICE_UDS_LENGTH, digest);

    // Derive CDI based on UDS and RIoT Core "measurement"
    DiceSHA256_2(digest, DICE_DIGEST_LENGTH, rDigest, DICE_DIGEST_LENGTH, CDI);

    // Don't use CDI directly
    RiotCrypt_Hash(digest, RIOT_DIGEST_LENGTH, CDI, DICE_DIGEST_LENGTH);

    // Derive DeviceID key pair from CDI
    RiotCrypt_DeriveEccKey(&deviceIDPub,
        &deviceIDPriv,
        digest, RIOT_DIGEST_LENGTH,
        (const uint8_t *)RIOT_LABEL_IDENTITY,
        lblSize(RIOT_LABEL_IDENTITY));

    // Combine CDI and FWID, result in digest
    RiotCrypt_Hash2(digest, RIOT_DIGEST_LENGTH,
        digest, RIOT_DIGEST_LENGTH,
        Fwid, RIOT_DIGEST_LENGTH);

    // Derive Alias key pair from CDI and FWID
    RiotCrypt_DeriveEccKey(&aliasKeyPub,
        &aliasKeyPriv,
        digest, RIOT_DIGEST_LENGTH,
        (const uint8_t *)RIOT_LABEL_ALIAS,
        lblSize(RIOT_LABEL_ALIAS));

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

    // Copy Alias Key Certificate
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
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &deviceIDPub);

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
        // Generating "root"-signed DeviceID certificate
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &deviceIDPub);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, (RIOT_ECC_PRIVATE *)eccRootPrivBytes);

        RiotCrypt_Verify(derCtx.Buffer, derCtx.Position, &tbsSig, (RIOT_ECC_PUBLIC *)eccRootPubBytes);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
    }

    // Copy DeviceID Certificate or CSR
    length = sizeof(PEM);
    DERtoPEM(&derCtx, CERT_TYPE, PEM, &length);
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

    // Generate "root" CA certficiate
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetRootCertTBS(&derCtx, &x509RootTBSData, (RIOT_ECC_PUBLIC*)eccRootPubBytes);

    // Self-sign the "root" Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

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

    return 0;
}

#ifdef DEBUG
void HexConvert(uint8_t* in, int inLen, char* outBuf, int outLen)
    {
        int pos = 0;
        for (int j = 0; j < inLen; j++)
        {
            int err = sprintf_s(outBuf + pos, outLen - j * 2, "%02X", in[j]);
            pos += 2;
            if (err == -1) return;
        }
        return;
    }
void PrintHex(uint8_t* buf, int bufLen)
{
    printf("\n");
    for (int j = 0; j < bufLen; j++)
    {
        //int val = (int) buf[j];
        printf("%02x", buf[j]);
    }
    printf("\n");
    char buffer[2048];
    HexConvert(buf, bufLen, buffer, 2048);
    OutputDebugStringA("\n");
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
    return;
}
void WriteBinaryFile(const char* fileName, uint8_t* buf, int bufLen)
{
    FILE* f;
    errno_t err = fopen_s(&f, fileName, "wb");
    if (err != 0)return;
    int len = (int)fwrite(buf, 1, bufLen, f);
    if (len != bufLen)return;
    int res = fclose(f);
    if (res != 0)return;
    return;
}
void WriteTextFile(const char* fileName, uint8_t* buf, int bufLen, uint8_t append)
{
    FILE* f;
    char* mode = append ? "a+t" : "wt";
    errno_t err = fopen_s(&f, fileName, mode);
    if (err != 0)return;
    int len = (int)fwrite(buf, 1, bufLen, f);
    if (len != bufLen)return;
    int res = fclose(f);
    if (res != 0)return;
    return;
}
#endif
