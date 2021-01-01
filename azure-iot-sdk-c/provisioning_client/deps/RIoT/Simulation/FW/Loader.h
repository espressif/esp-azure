/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "RIoT.h"
#include "RIoTSim.h"

#ifdef LOADER_EXPORTS
#define FW_API __declspec(dllexport)
#else
#define FW_API __declspec(dllimport)
#endif

FW_API void FirmwareEntry(
    char                *rootCert,
    RIOT_ECC_PUBLIC     *DeviceIDPub,
    char                *DeiceCert,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PRIVATE    *AliasKeyPriv,
    char                *AliasKeyCert
);

#ifdef __cplusplus
}
#endif
