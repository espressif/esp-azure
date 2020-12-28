// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef    _MEMORY_FP_H_
#define    _MEMORY_FP_H_

#include "umock_c/umock_c_prod.h"
#include "azure_utpm_c/BaseTypes.h"
#include "azure_utpm_c/TPMB.h"

#ifdef __cplusplus
extern "C"
{
#endif

//*** MemoryCopy()
// This is an alias for memmove. This is used in place of memcpy because
// some of the moves may overlap and rather than try to make sure that
// memmove is used when necessary, it is always used.
// The #if 0 is used to prevent instantiation of the MemoryCopy function so that
// the #define is always used
MOCKABLE_FUNCTION(, void, MemoryCopy, void*, dest, const void*, src, int, sSize);

//*** MemoryEqual()
// This function indicates if two buffers have the same values in the indicated
// number of bytes.
// return type: BOOL
//      TRUE    all octets are the same
//      FALSE   all octets are not the same
BOOL
MemoryEqual(
    const void      *buffer1,       // IN: compare buffer1
    const void      *buffer2,       // IN: compare buffer2
    unsigned int     size           // IN: size of bytes being compared
    );

//*** MemoryCopy2B()
// This function copies a TPM2B. This can be used when the TPM2B types are
// the same or different.
//
// This function returns the number of octets in the data buffer of the TPM2B.
MOCKABLE_FUNCTION(, INT16, MemoryCopy2B, TPM2B*, dest, const TPM2B*, source, unsigned int, dSize);

//*** MemoryConcat2B()
// This function will concatenate the buffer contents of a TPM2B to an
// the buffer contents of another TPM2B and adjust the size accordingly
//      ('a' := ('a' | 'b')).
void
MemoryConcat2B(
    TPM2B           *aInOut,        // IN/OUT: destination 2B
    TPM2B           *bIn,           // IN: second 2B
    unsigned int     aMaxSize       // IN: The size of aInOut.buffer (max values for
                                    //     aInOut.size)
    );

//*** MemoryEqual2B()
// This function will compare two TPM2B structures. To be equal, they
// need to be the same size and the buffer contexts need to be the same
// in all octets.
// return type: BOOL
//      TRUE    size and buffer contents are the same
//      FALSE   size or buffer contents are not the same
BOOL
MemoryEqual2B(
    const TPM2B     *aIn,           // IN: compare value
    const TPM2B     *bIn            // IN: compare value
    );

//*** MemorySet()
// This function will set all the octets in the specified memory range to
// the specified octet value.
// Note: A previous version had an additional parameter (dSize) that was
// intended to make sure that the destination would not be overrun. The
// problem is that, in use, all that was happening was that the value of
// size was used for dSize so there was no benefit in the extra parameter.
void MemorySet(
    void            *dest,
    int              value,
    size_t           size
    );

//*** MemoryPad2B()
// Function to pad a TPM2B with zeros and adjust the size.
void MemoryPad2B(
    TPM2B           *b,
    UINT16           newSize
    );

//*** Uint16ToByteArray()
// Function to write an integer to a byte array
void Uint16ToByteArray(
    UINT16              i,
    BYTE                *a
    );

//*** Uint32ToByteArray()
// Function to write an integer to a byte array
void Uint32ToByteArray(
    UINT32              i,
    BYTE                *a
    );

//*** Uint64ToByteArray()
// Function to write an integer to a byte array
void Uint64ToByteArray(
    UINT64               i,
    BYTE                *a
    );

//*** ByteArrayToUint16()
// Function to write an integer to a byte array
UINT16 ByteArrayToUint16(
    BYTE                *a
    );

//*** ByteArrayToUint32()
// Function to write an integer to a byte array
UINT32 ByteArrayToUint32(
    BYTE                *a
    );

//*** ByteArrayToUint64()
// Function to write an integer to a byte array
UINT64 ByteArrayToUint64(BYTE* a);

#ifdef __cplusplus
}
#endif

#endif  // _MEMORY_FP_H_
