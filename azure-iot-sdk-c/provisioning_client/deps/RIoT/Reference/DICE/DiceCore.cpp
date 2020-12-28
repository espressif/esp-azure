/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "stdafx.h"

// DICE definitions
#define DICE_UDS_LENGTH         0x20
#define DICE_DIGEST_LENGTH      0x20

// On real hardware, the UDS MUST be kept in some form of protected storage.
const BYTE UDS[DICE_UDS_LENGTH] = {
    0xb5, 0x85, 0x94, 0x93, 0x66, 0x1e, 0x2e, 0xae,
    0x96, 0x77, 0xc5, 0x5d, 0x59, 0x0b, 0x92, 0x94,
    0xe0, 0x94, 0xab, 0xaf, 0xd7, 0x40, 0x78, 0x7e,
    0x05, 0x0d, 0xfe, 0x6d, 0x85, 0x90, 0x53, 0xa0 };

// Storage for Compound Device Identifier
BYTE CDI[DICE_DIGEST_LENGTH] = { 0x00 };

// Simulation-only definitions
#define DEFAULT_RIOT_PATH       L"riot.dll"     // Contains RIoT Invariant Code
#define DEFAULT_LOADER_PATH     L"FW.dll"       // Our simulated FW
#define RIOT_ENTRY              "RiotStart"     // RIoT Core entry point 
typedef void(__cdecl* fpRiotStart)(const BYTE *, const uint32_t, const TCHAR *);

// Simulation only: This function finds the in-memory base-offset and size
// of RIoT .text section.  On real hardware DICE would have knowledge of
// the physical location and size of RIoT Invariant Code.
BOOLEAN DiceGetRiotInfo(HINSTANCE riotDLL, DWORD *riotCore, DWORD *riotSize);

int _tmain(int argc, TCHAR* argv[])
//
// This is the main entrypoint for this reference simulation.  It does some
// initial setup and falls through to Boot.  The code after the Boot label
// simulates device power-on-reset.  Everything between start of _tmain and
// the Boot label can be safely ignored, as it is uninteresting.
//
{
    uint8_t uDigest[DICE_DIGEST_LENGTH] = { 0 };
    uint8_t rDigest[DICE_DIGEST_LENGTH] = { 0 };
    TCHAR *riotImagePath, *loaderImagePath;
    uint8_t *riotCore;
    DWORD riotSize, offset;
    HINSTANCE hRiotDLL;

    // Assume default paths
    riotImagePath = DEFAULT_RIOT_PATH;
    loaderImagePath = DEFAULT_LOADER_PATH;

    // Check for path to riot image
    if (argc > 1)
    {
        if (wcslen(argv[1]) > MAX_PATH)
        {
            fprintf(stderr, "ERROR: Bad RIoT path.\n");
            goto Error;
        }
        else
        {
            riotImagePath = argv[1];
        }
        // Check for path to loader image
        if (argc > 2)
        {
            if (wcslen(argv[2]) > MAX_PATH)
            {
                fprintf(stderr, "ERROR: Bad Loader path.\n");
                goto Error;
            }
            else
            {
                loaderImagePath = argv[2];
            }
        }
    }

Boot:
    // ++
    // DICE is responsible for the following actions:
    //     1. Measure RIoT Core
    //     2. Generate CDI based on UDS and RIoT Core measurement
    //     3. Close access to UDS and pass CDI in transition to RIoT
    //
    // To accomplish this, we first need to take some steps to setup our
    // simulated device. This doesn't happen on real hardware.
    // --

    // Power-on "device"
    printf("DICE: Begin\n");

//DiceInit:

    // Load DLL containing RIoT Core.
    hRiotDLL = LoadLibrary(riotImagePath);
    if (hRiotDLL == NULL) {
        fprintf(stderr, "ERROR: Failed to load RIoT Framework\n");
        goto Error;
    }

    // Locate RiotStart
    fpRiotStart RiotStart = (fpRiotStart)GetProcAddress(hRiotDLL, RIOT_ENTRY);
    if (!RiotStart) {
        fprintf(stderr, "ERROR: Failed to locate RiotStart\n");
        goto Error;
    }

    // Get base offset and size of RIoT Invariant Code
    if (!DiceGetRiotInfo(hRiotDLL, &offset, &riotSize)) {
        fprintf(stderr, "ERROR: Failed to locate RIoT Invariant code\n");
        goto Error;
    }

    // Calculate base VA of RIoT Invariant Code
    riotCore = (uint8_t *)((uint64_t)hRiotDLL + offset);

    // UDS
    printf("DICE: UDS Bytes:\n\t");
    for (int i = 0; i < DICE_UDS_LENGTH; i++) {
        printf("%02X", UDS[i]);
    }
    printf("\n");
    
    // RIoTStart address
    printf("DICE: RiotStart: %p\n", RiotStart);

// DiceCore:

    // The hashing functions below are only used for this simulated devivce
    // and in those instances where an MCU doesn't include one in HW.

    // Measure RIoT Invariant Code
    printf("DICE: Measure RIoT Invariant Code:\n\t");
    DiceSHA256(riotCore, riotSize, rDigest);
    for (int i = 0; i < DICE_UDS_LENGTH; i++) {
        printf("%02X", rDigest[i]);
    }
    printf("\n");

    // Don't use UDS directly
    DiceSHA256(UDS, DICE_UDS_LENGTH, uDigest);
    
    // Derive CDI value
    printf("DICE: Derive CDI\n\t");
    DiceSHA256_2(uDigest, DICE_DIGEST_LENGTH, rDigest, DICE_DIGEST_LENGTH, CDI);
    for (int i = 0; i < DICE_UDS_LENGTH; i++) {
        printf("%02X", CDI[i]);
    }
    printf("\n");

    // Clean up potentially sensative data
    memset(uDigest, 0x00, DICE_DIGEST_LENGTH);
    memset(rDigest, 0x00, DICE_DIGEST_LENGTH);

    // Handoff to RIoT. Note that we pass loaderImagePath here only so
    // when our "device" is powered on, we can take as an argument 
    // different "FW" images.  On a real device DICE would not tell
    // RIoT Core what code to invoke next.  This would be a fixed
    // address in flash and (probably) unknown to DICE.
    printf("DICE: Transition to RIoTStart\n");
    RiotStart(CDI, DICE_DIGEST_LENGTH, loaderImagePath);

    // We treat a return as a power-cycle for our simulated device.
    // Tear down our RIoT image and "reboot".
    if (!FreeLibrary(hRiotDLL))
    {
        fprintf(stderr, "ERROR: Failed to unload RIoT Framework\n");
        goto Error;
    }

    // Pause briefly
    Sleep(500);
    goto Boot;

Error:
    return -1;
}

BOOLEAN
DiceGetRiotInfo(
    HINSTANCE   riotDLL,
    DWORD      *riotCore,
    DWORD      *riotSize
)
// This is a quick and dirty function to find the .text (CODE) section of
// the RIoT image. We don't do anything like this on real hardware because,
// on real hardware, DICE has the base address and size of RIoT Invariant
// Code as constant values resolved at link time (at the latest).
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)riotDLL;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PCHAR)dosHeader + (ULONG)(dosHeader->e_lfanew));
    PIMAGE_OPTIONAL_HEADER optionalHeader = &(ntHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(optionalHeader + 1);
    PIMAGE_FILE_HEADER fileHeader = &(ntHeader->FileHeader);
    ULONG nSections = fileHeader->NumberOfSections, i;

    for (i = 0; i < nSections; i++)
    {
        if (!strcmp((char *)sectionHeader->Name, ".text"))
        {
            *riotCore = sectionHeader->VirtualAddress;
            *riotSize = sectionHeader->Misc.VirtualSize;
            return TRUE;
        }
        sectionHeader++;
    }
    return FALSE;
}