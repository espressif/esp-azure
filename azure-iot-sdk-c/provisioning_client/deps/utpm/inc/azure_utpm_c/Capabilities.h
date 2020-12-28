// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef     _CAPABILITIES_H
#define     _CAPABILITIES_H

#define    MAX_CAP_DATA         (MAX_CAP_BUFFER-sizeof(TPM_CAP)-sizeof(UINT32))
#define    MAX_CAP_ALGS         (MAX_CAP_DATA/sizeof(TPMS_ALG_PROPERTY))
#define    MAX_CAP_HANDLES      (MAX_CAP_DATA/sizeof(TPM_HANDLE))
#define    MAX_CAP_CC           (MAX_CAP_DATA/sizeof(TPM_CC))
#define    MAX_TPM_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PROPERTY))
#define    MAX_PCR_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PCR_SELECT))
#define    MAX_ECC_CURVES       (MAX_CAP_DATA/sizeof(TPM_ECC_CURVE))
#define    MAX_TAGGED_POLICIES  (MAX_CAP_DATA/sizeof(TPMS_TAGGED_POLICY))

#endif
