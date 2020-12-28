// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//
// This file contains extra TPM2B structures
//

#ifndef _TPMB_H
#define _TPMB_H

// TPM2B Types
typedef struct {
    UINT16          size;
    BYTE            buffer[1];
} TPM2B, *P2B;
typedef const TPM2B     *PC2B;

// This macro helps avoid having to type in the structure in order to create
// a new TPM2B type that is used in a function.
#define TPM2B_TYPE(name, bytes)             \
    typedef union {                         \
        struct  {                           \
            UINT16  size;                   \
            BYTE    buffer[(bytes)];        \
        } t;                                \
        TPM2B   b;                          \
    } TPM2B_##name

// This macro defines a TPM2B with a constant character value. This macro
// sets the size of the string to the size minus the terminating zero byte.
// This lets the user of the label add their terminating 0. This method
// is chosen so that existing code that provides a label will continue
// to work correctly.
#define TPM2B_STRING(name, value)           \
    static const union {                    \
        struct  {                           \
            UINT16  size;                   \
            BYTE    buffer[sizeof(value)];  \
        } t;                                \
        TPM2B   b;                          \
    } name##_ = {{sizeof(value), {value}}}; \
    const TPM2B       *name = &name##_.b

// Macro to instance and initialize a TPM2B value
#define TPM2B_INIT(TYPE, name)  \
    TPM2B_##TYPE    name = {sizeof(name.t.buffer), {0}}

#define TPM2B_BYTE_VALUE(bytes) TPM2B_TYPE(bytes##_BYTE_VALUE, bytes)


#endif
