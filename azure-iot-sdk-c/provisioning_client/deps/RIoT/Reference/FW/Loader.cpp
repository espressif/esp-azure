/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "stdafx.h"

// There are lots of ways to force a new FWID value. However, to
// maintain a consistent FWID value accross "boots", the default
// linker option that randomizes base addresses must be disabled.

FW_API void FirmwareEntry(
    ecc_publickey    *DeviceIDPub,
    ecc_publickey    *AliasKeyPub,
    ecc_privatekey   *AliasKeyPriv,
    char             *AliasKeyCert
)
{
    UINT32 i;

    printf("FW: Begin.\n");
    printf("FW: AliasKeyPub:\n\tx: ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", AliasKeyPub->x.data[i]);
    }
    printf("\n\ty: ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", AliasKeyPub->y.data[i]);
    }
    printf("\nFW: AliasKeyPriv:\n\t   ");
    for (i = 0; i < ((BIGLEN)-1); i++) {
        printf("%08X", AliasKeyPriv->data[i]);
    }

    printf("\nFW: AliasKeyCertificate:\n %s", AliasKeyCert);

    i = 5;
    do {
        printf("\rFW: \"Running\" \\");
        Sleep(100);
        printf("\rFW: \"Running\" |");
        Sleep(100);
        printf("\rFW: \"Running\" /");
        Sleep(100);
        printf("\rFW: \"Running\" -");
        Sleep(100);
    } while (i--);
    
    printf("\nFW: Reboot!\n");
    Sleep(300);
	return;
}
