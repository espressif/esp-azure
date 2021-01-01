/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#ifndef _RIOT_STATUS_H
#define _RIOT_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RIOT_STATUS {
    RIOT_SUCCESS = 0,
    RIOT_FAILURE = RIOT_SUCCESS + 0x80,
    RIOT_INVALID_PARAMETER,
    RIOT_INVALID_STATE,
} RIOT_STATUS;

#ifdef __cplusplus
}
#endif

#endif
