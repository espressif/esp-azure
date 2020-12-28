/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#ifndef _RIOT_H
#define _RIOT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "RiotStatus.h"
#include "RiotCrypt.h"

#define RIOT_SUCCESS(a) (a == (RIOT_OK))

//
// Key derivation labels used by both RIoT Devices and External Infrastructure
//
#define RIOT_LABEL_IDENTITY     "Identity"
#define RIOT_LABEL_ALIAS        "Alias"
#define RIOT_LABEL_PROTECTOR    "Encrypt"
#define RIOT_LABEL_INTEGRITY    "HMAC"
#define RIOT_LABEL_AIK          "AikProtector"
#define RIOT_LABEL_SK           "Sealing"
#define RIOT_LABEL_MK           "Migration"
#define RIOT_LABEL_AK           "Attestation"

//
// Macro for label sizes (skip strlen()).
//
#define lblSize(a)          (sizeof(a) - 1)

#ifdef __cplusplus
}
#endif

#endif
