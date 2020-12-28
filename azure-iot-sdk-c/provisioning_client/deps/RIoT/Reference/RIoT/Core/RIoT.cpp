/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/

#include "stdafx.h"

// There are lots of ways to force a new CDI value. However, to
// maintain a consistent CDI value accross "boots", the default
// linker option that randomizes base addresses must be disabled.

// For our simulated device, it's fine that these are in the global
// data for the RIoT DLL. On real hardware, these are passed via some
// shared data area or in a hardware security module.
RIOT_ECC_PUBLIC     DeviceIDPub;
RIOT_ECC_PUBLIC     AliasKeyPub;
RIOT_ECC_PRIVATE    AliasKeyPriv;
BYTE                FWID[RIOT_DIGEST_LENGTH];
char                Cert[DER_MAX_PEM];
char               *CSRBuffer = NULL; // Optional, !used when NULL

// Device Firmware may prefer PEM encoded DeviceID/Alias Keys. This is not
// the default. Define RIOT_ENCODED_KEYS here and adjust the buffer copies
// below to support PEM-encoded keys for device firmware.
// #define RIOT_ENCODED_KEYS

// The static data fields that make up the x509 "to be signed" region
RIOT_X509_TBS_DATA x509TBSData = { { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E },
                                   "RIoT Core", "MSR_TEST", "US",
                                   "170101000000Z", "370101000000Z",
                                   "RIoT Device", "MSR_TEST", "US" };

// Name and function pointer corresponding to the current FW image
#define FIRMWARE_ENTRY        "FirmwareEntry"
typedef void(__cdecl* fpFirmwareEntry)(
    ecc_publickey    *DeviceIDPub,
    ecc_publickey    *AliasKeyPub,
    ecc_privatekey   *AliasKeyPriv,
    char             *AliasKeyCert
    );

// Simulation only: This function finds the in-memory base-offset and size
// of RIoT .text section. On real hardware RIoT would have knowledge of
// the physical location and size of device firmware.
BOOLEAN RiotGetFWInfo(HINSTANCE fwDLL, DWORD *baseOffset, DWORD *length);

RIOT_API void
RiotStart(
    const BYTE *CDI,
    const uint32_t CDILen,
    const TCHAR *FWImagePath
)
{
    BYTE                cerBuffer[DER_MAX_TBS];
    BYTE                derBuffer[DER_MAX_TBS];
    BYTE                cDigest[RIOT_DIGEST_LENGTH];
    RIOT_ECC_PRIVATE    deviceIDPriv;
    RIOT_ECC_SIGNATURE  tbsSig;
    DERBuilderContext   derCtx;
    DERBuilderContext   cerCtx;
    fpFirmwareEntry     FirmwareEntry;
    BYTE               *fwImage;
    uint32_t            length;
    DWORD               fwSize, offset, i;
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

    // Device Identity Key pair
    printf("RIOT: deviceIDPublic:\n\tx: ");
    for (i = 0; i < ((BIGLEN) - 1); i++) {
        printf("%08X", DeviceIDPub.x.data[i]);
    }
    printf("\n\ty: ");
    for (i = 0; i < ((BIGLEN) - 1); i++) {
        printf("%08X", DeviceIDPub.y.data[i]);
    }
    printf("\nRIOT: deviceIDPrivate:\n\t   ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", deviceIDPriv.data[i]);
    }
    printf("\n");

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

    // Clean up potentially sensative data
    memset(cDigest, 0x00, RIOT_DIGEST_LENGTH);
    
    // Build the TBS (to be signed) region of Alias Key Certificate
    DERInitContext(&cerCtx, cerBuffer, DER_MAX_TBS);
    X509GetAliasCertTBS(&cerCtx, &x509TBSData,
                        &AliasKeyPub, &DeviceIDPub,
                        FWID, RIOT_DIGEST_LENGTH);

    // Sign the Alias Key Certificate's TBS region
    RiotCrypt_Sign(&tbsSig, cerCtx.Buffer, cerCtx.Position, &deviceIDPriv);

    // Generate Alias Key Certificate by signing the TBS region
    X509MakeAliasCert(&cerCtx, &tbsSig);

    // Optionally,  make a CSR for the DeviceID
    if (CSRBuffer != NULL) {

        // Initialize, create CSR TBS region
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        X509GetDERCsrTbs(&derCtx, &x509TBSData, &DeviceIDPub);

        // Sign the Alias Key Certificate's TBS region
        RiotCrypt_Sign(&tbsSig, derCtx.Buffer, derCtx.Position, &deviceIDPriv);

        // Create CSR for DeviceID
        X509GetDERCsr(&derCtx, &tbsSig);

        // Copy CSR
        length = sizeof(CSRBuffer);
        DERtoPEM(&derCtx, CERT_REQ_TYPE, CSRBuffer, &length);
        CSRBuffer[length] = '\0';
    }

    // Copy Alias Key Certificate
    length = sizeof(Cert);
    DERtoPEM(&cerCtx, CERT_TYPE, Cert, &length);
    Cert[length] = '\0';

#ifdef RIOT_ENCODE_KEYS

    // Copy DeviceID Public
    length = sizeof(PEM);
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetDEREccPub(&derCtx, DeviceIDPub);
    DERtoPEM(&derCtx, PUBLICKEY_TYPE, PEM, &length);
    *DeviceIDPublicEncodedSize = length;
    memcpy(DeviceIDPublicEncoded, PEM, length);

    // Copy Alias Key Pair
    length = sizeof(PEM);
    DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
    X509GetDEREcc(&derCtx, AliasKeyPub, AliasKeyPriv);
    DERtoPEM(&derCtx, ECC_PRIVATEKEY_TYPE, PEM, &length);
    *AliasKeyEncodedSize = length;
    memcpy(AliasKeyEncoded, PEM, length);

#endif

    // Transfer control to firmware
    FirmwareEntry(&DeviceIDPub, &AliasKeyPub, &AliasKeyPriv, Cert);

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