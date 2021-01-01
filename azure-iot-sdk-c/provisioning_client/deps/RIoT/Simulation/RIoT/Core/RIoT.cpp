/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include "stdafx.h"

#ifdef _MSC_VER
#pragma warning(disable : 4127) // conditional expressionn is constant
#endif

// There are lots of ways to force a new CDI value. However, to
// maintain a consistent CDI value accross "boots", the default
// linker option that randomizes base addresses must be disabled.

// For our simulated device, it's fine that these are in the global
// data for the RIoT DLL. On real hardware, these are passed via hardware
// security module or shared data area.
RIOT_ECC_PUBLIC     DeviceIDPub;
RIOT_ECC_PUBLIC     AliasKeyPub;
RIOT_ECC_PRIVATE    AliasKeyPriv;
char                AliasCert[DER_MAX_PEM] = { 0 };
char                DeviceCert[DER_MAX_PEM] = { 0 };
char                r00tCert[DER_MAX_PEM] = { 0 };

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
RIOT_X509_TBS_DATA x509RootTBSData = { { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E , 0x6F, 0x70, 0x81 },
                                        "RIoT R00t", "MSR_TEST", "US",
                                        "170101000000Z", "370101000000Z",
                                        "RIoT R00t", "MSR_TEST", "US" };

// Selectors for DeviceID cert handling.  
#define RIOT_ROOT_SIGNED    0x00
#define RIOT_SELF_SIGNED    0x01
#define RIOT_CSR            0x02

// DeviceID cert type (root signed, default)
#define DEVICE_ID_CERT_TYPE RIOT_ROOT_SIGNED

// Simulated "root" signing keypair
RIOT_ECC_PUBLIC  eccRootPub;
RIOT_ECC_PRIVATE eccRootPriv;

// Name and function pointer corresponding to the current FW image
#define FIRMWARE_ENTRY        "FirmwareEntry"
typedef void(__cdecl* fpFirmwareEntry)(
    char                *r00tCert,
    RIOT_ECC_PUBLIC     *DeviceIDPub,
    char                *DeviceCert,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PRIVATE    *AliasKeyPriv,
    char                *AliasKeyCert
);

// Simulation only: This function finds the in-memory base-offset and size
// of the RIoT .text section. On real hardware RIoT would have knowledge of
// the physical address and size of device firmware.
BOOLEAN RiotGetFWInfo(HINSTANCE fwDLL, DWORD *baseOffset, DWORD *length);

// Sets tbsData->SerialNumber to a quasi-random value derived from seedData
static void RiotSetSerialNumber(RIOT_X509_TBS_DATA* tbsData, const uint8_t* seedData, size_t seedLen);

// Used to populate "root" signing keypair
static void RiotGetRootKey(RIOT_ECC_PUBLIC *Pub, RIOT_ECC_PRIVATE *Priv);

RIOT_API void
RiotStart(
    const BYTE *CDI,
    const uint32_t CDILen,
    const TCHAR *FWImagePath
)
{
    BYTE                derBuffer[DER_MAX_TBS];
    BYTE                cDigest[RIOT_DIGEST_LENGTH];
    BYTE                FWID[RIOT_DIGEST_LENGTH];
    char                buffer[1024];
    RIOT_ECC_PRIVATE    deviceIDPriv;
    RIOT_ECC_SIGNATURE  tbsSig;
    DERBuilderContext   derCtx;
    fpFirmwareEntry     FirmwareEntry;
    BYTE               *fwImage;
    uint32_t            length, PEMtype;
    DWORD               fwSize, offset;
    HINSTANCE           fwDLL;

    // Parameter validation
    if (!(CDI) || (CDILen != SHA256_DIGEST_LENGTH)) {
        return;
    }

    // RIoT Begin
    printf("RIOT: Begin\n");

    // Don't use CDI directly
    RiotCrypt_Hash(cDigest, RIOT_DIGEST_LENGTH, CDI, CDILen);

    // Derive DeviceID key pair from CDI
    RiotCrypt_DeriveEccKey(&DeviceIDPub,
                           &deviceIDPriv,
                           cDigest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_IDENTITY,
                           lblSize(RIOT_LABEL_IDENTITY));

    // Set the serial number for DeviceID certificate
    RiotSetSerialNumber(&x509DeviceTBSData, cDigest, RIOT_DIGEST_LENGTH);

    // Output Device Identity Key pair
    printf("RIOT: deviceIDPublic:\n");
    mbedtls_mpi_write_string(&DeviceIDPub.X, 16, buffer, sizeof(buffer), &length);
    printf("\tx: %s\n", buffer);
    mbedtls_mpi_write_string(&DeviceIDPub.Y, 16, buffer, sizeof(buffer), &length);
    printf("\ty: %s\n", buffer);
    printf("RIOT: deviceIDPrivate:\n");
    mbedtls_mpi_write_string(&deviceIDPriv, 16, buffer, sizeof(buffer), &length);
    printf("\t%s\n", buffer);

    // Locate firmware image
    fwDLL = LoadLibrary(FWImagePath);
    if (fwDLL == NULL) {
        printf("RIOT: ERROR: Failed to load firmware image.\n");
        return;
    }
    
    // Locate entry point for FW
    FirmwareEntry = (fpFirmwareEntry)GetProcAddress(fwDLL, FIRMWARE_ENTRY);
    if (!FirmwareEntry) {
        printf("RIOT: ERROR: Failed to locate fw start\n");
        return;
    }

    // Get base offset and size of FW image
    if (!RiotGetFWInfo(fwDLL, &offset, &fwSize)) {
        fprintf(stderr, "FW: Failed to locate FW code\n");
        return;
    }

    // Calculate base VA of FW code
    fwImage = (BYTE *)((uint64_t)fwDLL + offset);

    // Measure FW, i.e., calculate FWID
    RiotCrypt_Hash(FWID, RIOT_DIGEST_LENGTH, fwImage, fwSize);

    // Combine CDI and FWID, result in cDigest
    RiotCrypt_Hash2(cDigest, RIOT_DIGEST_LENGTH,
                    cDigest, RIOT_DIGEST_LENGTH,
                    FWID,    RIOT_DIGEST_LENGTH);

    // Derive Alias key pair from CDI and FWID
    RiotCrypt_DeriveEccKey(&AliasKeyPub,
                           &AliasKeyPriv,
                           cDigest, RIOT_DIGEST_LENGTH,
                           (const uint8_t *)RIOT_LABEL_ALIAS,
                           lblSize(RIOT_LABEL_ALIAS));

    // With the Alias Key pair derived, we can now Seed DRBG
    RiotCrypt_SeedDRBG((uint8_t*)&AliasKeyPriv, sizeof(RIOT_ECC_PRIVATE), NULL, 0);

    // Set the serial number
    RiotSetSerialNumber(&x509AliasTBSData, cDigest, RIOT_DIGEST_LENGTH);

    // Clean up potentially sensative data
    memset(cDigest, 0x00, RIOT_DIGEST_LENGTH);
    
    // Output Alias Key pair
    printf("RIOT: Alias Key (pub):\n");
    mbedtls_mpi_write_string(&AliasKeyPub.X, 16, buffer, sizeof(buffer), &length);
    printf("\tx: %s\n", buffer);
    mbedtls_mpi_write_string(&AliasKeyPub.Y, 16, buffer, sizeof(buffer), &length);
    printf("\ty: %s\n", buffer);
    printf("RIOT: Alias Key (priv):\n");
    mbedtls_mpi_write_string(&AliasKeyPriv, 16, buffer, sizeof(buffer), &length);
    printf("\t%s\n", buffer);

    // Build the TBS (to be signed) region of Alias Key Certificate
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetAliasCertTBS(&derCtx, &x509AliasTBSData,
                        &AliasKeyPub, &DeviceIDPub,
                        FWID, RIOT_DIGEST_LENGTH);

    // Sign the Alias Key Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

    // Generate Alias Key Certificate
    X509MakeAliasCert(&derCtx, &tbsSig);

    // Copy Alias Key Certificate
    length = sizeof(AliasCert);
    DERtoPEM(&derCtx, CERT_TYPE, AliasCert, &length);
    AliasCert[length] = '\0';

    // This reference supports generation of either: a "root"-signed DeviceID
    // certificate, or a certificate signing request for the DeviceID Key. 
    // In a production device, Alias Key Certificates are normally leaf certs
    // that chain back to a known root CA. This is difficult to represent in
    // simulation since different vendors each have different manufacturing 
    // processes and CAs.

    if (DEVICE_ID_CERT_TYPE == RIOT_SELF_SIGNED) {
        // Generating self-signed DeviceID certificate

        x509DeviceTBSData.IssuerCommon  = x509DeviceTBSData.SubjectCommon;
        x509DeviceTBSData.IssuerOrg     = x509DeviceTBSData.IssuerOrg;
        x509DeviceTBSData.IssuerCountry = x509DeviceTBSData.SubjectCountry;

        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &DeviceIDPub, NULL, 0);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
        PEMtype = CERT_TYPE;
    }
    else if (DEVICE_ID_CERT_TYPE == RIOT_CSR) {
        // Generating CSR
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDERCsrTbs(&derCtx, &x509AliasTBSData, &DeviceIDPub);

        // Sign the Alias Key Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Create CSR for DeviceID
        X509GetDERCsr(&derCtx, &tbsSig);
        PEMtype = CERT_REQ_TYPE;
    }
    else {
        // Generating "root"-signed DeviceID certificate
        uint8_t rootPubBuffer[(RIOT_COORDMAX * 2 + 1)];
        uint32_t rootPubBufLen = (RIOT_COORDMAX * 2 + 1);

        // Get "root" signing key
        RiotGetRootKey(&eccRootPub, &eccRootPriv);

        // Export "root" key bytes and prepare device cert
        RiotCrypt_ExportEccPub(&eccRootPub, rootPubBuffer, &rootPubBufLen);
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDeviceCertTBS(&derCtx, &x509DeviceTBSData, &DeviceIDPub, rootPubBuffer, rootPubBufLen);

        // Sign the DeviceID Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &eccRootPriv);

        // Sanity check signature
        RiotCrypt_Verify(derCtx.Buffer, derCtx.Position, &tbsSig, &eccRootPub);

        // Generate DeviceID Certificate
        X509MakeDeviceCert(&derCtx, &tbsSig);
        PEMtype = CERT_TYPE;
    }

    // Copy DeviceID Certificate
    length = sizeof(DeviceCert);
    DERtoPEM(&derCtx, PEMtype, DeviceCert, &length);
    DeviceCert[length] = '\0';

    // If necessary, generate "root" CA cert
    if (DEVICE_ID_CERT_TYPE == RIOT_ROOT_SIGNED)
    {
        // Generate "root" CA certficiate
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetRootCertTBS(&derCtx, &x509RootTBSData, &eccRootPub);

        // Self-sign the "root" Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &eccRootPriv);

        // Generate "root" CA cert
        X509MakeRootCert(&derCtx, &tbsSig);

        // Copy "root" CA Certificate
        length = sizeof(r00tCert);
        DERtoPEM(&derCtx, CERT_TYPE, r00tCert, &length);
    }

    // Transfer control to firmware
    FirmwareEntry(r00tCert, &DeviceIDPub, DeviceCert, &AliasKeyPub, &AliasKeyPriv, AliasCert);

    return;
}

BOOLEAN
RiotGetFWInfo(
    HINSTANCE   fwDLL,
    DWORD      *baseOffset,
    DWORD      *length
)
// This is a quick and dirty function to find the .text (CODE) section of
// the FW image. We don't do anything like this on real hardware because,
// on real hardware, RIoT has the base address and size of the FW are
// as constant values resolved at build/link time.
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fwDLL;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PCHAR)dosHeader + (ULONG)(dosHeader->e_lfanew));
    PIMAGE_OPTIONAL_HEADER optionalHeader = &(ntHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(optionalHeader + 1);
    PIMAGE_FILE_HEADER fileHeader = &(ntHeader->FileHeader);
    ULONG nSections = fileHeader->NumberOfSections, i;

    for (i = 0; i < nSections; i++)
    {
        if (!strcmp((char *)sectionHeader->Name, ".text"))
        {
            *baseOffset = sectionHeader->VirtualAddress;
            *length = sectionHeader->Misc.VirtualSize;
            return TRUE;
        }
        sectionHeader++;
    }
    return FALSE;
}

static void
RiotSetSerialNumber(
    RIOT_X509_TBS_DATA  *tbsData, 
    const uint8_t       *seedData,
    size_t               seedLen
)
// Set the tbsData serial number to 8 bytes of data derived from seedData
{
    
    uint8_t hashBuf[RIOT_DIGEST_LENGTH];
    // SHA-1 hash of "DICE SEED" == 6e785006 84941d8f 7880520c 60b8c7e4 3f1a3c00
    uint8_t seedExtender[20] = { 0x6e, 0x78, 0x50, 0x06, 0x84, 0x94, 0x1d, 0x8f, 0x78, 0x80,
                                 0x52, 0x0c, 0x60, 0xb8, 0xc7, 0xe4, 0x3f, 0x1a, 0x3c, 0x00 };

    RiotCrypt_Hash2(hashBuf, sizeof(hashBuf), seedData, seedLen, seedExtender, sizeof(seedExtender));

    // Take first 8 bytes to form serial number
    memcpy(tbsData->SerialNum, hashBuf, RIOT_X509_SNUM_LEN);

    // DER encoded serial number must be positive and the first byte must not be zero
    tbsData->SerialNum[0] &= (uint8_t)0x7f;
    tbsData->SerialNum[0] |= (uint8_t)0x01;

    return;
}

static void
RiotGetRootKey(
    RIOT_ECC_PUBLIC *Pub,
    RIOT_ECC_PRIVATE *Priv
)
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
    uint8_t rootD[RIOT_COORDMAX] = {
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
    mbedtls_mpi_read_binary(Priv, rootD, RIOT_COORDMAX);
    memset(rootD, 0, sizeof(rootD));
    return;
}