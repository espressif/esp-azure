/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include "stdafx.h"

// There are lots of ways to force a new FWID value. However, to
// maintain a consistent FWID value accross "boots", the default
// linker option that randomizes base addresses must be disabled.

FW_API void FirmwareEntry(
    char                *r00tCert,
    RIOT_ECC_PUBLIC     *DeviceIDPub,
    char                *DeviceCert,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PRIVATE    *AliasKeyPriv,
    char                *AliasKeyCert
)
{
    UINT32 i;

    UNREFERENCED_PARAMETER(DeviceIDPub);
    UNREFERENCED_PARAMETER(AliasKeyPub);
    UNREFERENCED_PARAMETER(AliasKeyPriv);

    printf("FW: Begin.\n");

    printf("FW: r00tCertificate:\n %s", r00tCert);
    printf("\nFW: DeviceCertificate:\n %s", DeviceCert);
    printf("\nFW: AliasKeyCertificate:\n %s", AliasKeyCert);

    i = 50;
    do {
        printf("\rFW: \"Running\" \\");
        Sleep(10);
        printf("\rFW: \"Running\" |");
        Sleep(10);
        printf("\rFW: \"Running\" /");
        Sleep(10);
        printf("\rFW: \"Running\" -");
        Sleep(10);
    } while (i--);
    
    printf("\nFW: Reboot!\n");
    Sleep(300);
	return;
}
