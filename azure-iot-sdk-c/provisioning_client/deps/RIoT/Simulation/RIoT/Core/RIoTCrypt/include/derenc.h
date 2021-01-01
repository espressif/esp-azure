/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define DER_MAX_PEM     0x500
#define DER_MAX_TBS     0x500
#define DER_MAX_NESTED  0x10

//
// Context structure for the DER-encoder. This structure contains a fixed-
// length array for nested SEQUENCES (which imposes a nesting limit).
// The buffer use for encoded data is caller-allocted.
//
typedef struct
{
    uint8_t     *Buffer;        // Encoded data
    uint32_t     Length;        // Size, in bytes, of Buffer
    uint32_t     Position;      // Current buffer position

    // SETS, SEQUENCES, etc. can be nested. This array contains the start of
    // the payload for collection types and is set by  DERStartSequenceOrSet().
    // Collections are "popped" using DEREndSequenceOrSet().
    int CollectionStart[DER_MAX_NESTED];
    int CollectionPos;
} DERBuilderContext;

// We only have a small subset of potential PEM encodings
enum CertType {
    CERT_TYPE = 0,
    PUBLICKEY_TYPE,
    ECC_PRIVATEKEY_TYPE,
    CERT_REQ_TYPE,
    LAST_CERT_TYPE
};

void
DERInitContext(
    DERBuilderContext   *Context,
    uint8_t             *Buffer,
    uint32_t             Length
);

int
DERGetEncodedLength(
    DERBuilderContext   *Context
);


int
DERAddOID(
    DERBuilderContext   *Context,
    int                 *Values
);

int
DERAddUTF8String(
    DERBuilderContext   *Context,
    const char          *Str
);

int 
DERAddPrintableString(
    DERBuilderContext   *Context,
    const char          *Str
);


int
DERAddUTCTime(
    DERBuilderContext   *Context,
    const char          *Str
);

int
DERAddIntegerFromArray(
    DERBuilderContext   *Context,
    uint8_t             *Val,
    uint32_t            NumBytes
);

int
DERAddInteger(
    DERBuilderContext   *Context,
    int                 Val
);

int
DERAddShortExplicitInteger(
    DERBuilderContext   *Context,
    int                  Val
);

int
DERAddBoolean(
    DERBuilderContext   *Context,
    bool                 Val
);


int
DERAddBitString(
    DERBuilderContext   *Context,
    uint8_t             *BitString,
    uint32_t             BitStringNumBytes
);

int
DERAddOctetString(
    DERBuilderContext   *Context,
    uint8_t             *OctetString,
    uint32_t             OctetStringLen
);

int
DERStartSequenceOrSet(
    DERBuilderContext   *Context,
    bool                 Sequence
);

int
DERStartExplicit(
    DERBuilderContext   *Context,
    uint32_t             Num
);

int
DERStartEnvelopingOctetString(
    DERBuilderContext   *Context
);

int
DERStartEnvelopingBitString(
    DERBuilderContext   *Context
);

int
DERPopNesting(
    DERBuilderContext   *Context
);

int
DERGetNestingDepth(
    DERBuilderContext   *Context
);

int
DERTbsToCert(
    DERBuilderContext   *Context
);

int
DERtoPEM(
    DERBuilderContext   *Context,
    uint32_t            Type,
    char                *PEM,
    uint32_t            *Length
);

#ifdef __cplusplus
}
#endif
