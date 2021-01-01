/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#ifndef _RIOT_DLL_H
#define _RIOT_DLL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifdef RIOT_EXPORTS
#define RIOT_API __declspec(dllexport)
#else
#define RIOT_API __declspec(dllimport)
#endif

RIOT_API void RiotStart(const BYTE *, const uint32_t, const TCHAR *);

#ifdef __cplusplus
}
#endif

#endif