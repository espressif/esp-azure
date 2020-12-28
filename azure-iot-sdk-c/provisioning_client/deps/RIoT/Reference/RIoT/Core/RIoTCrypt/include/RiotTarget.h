#ifndef _RIOT_TARGET_H
#define _RIOT_TARGET_H
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

//
// 4-MAY-2015; RIoT adaptation (DennisMa;MSFT).
//
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

// TODO: Fix this so we actually get asserts on non-MSFT platforms
#ifndef _MSC_VER
#define assert(expr)    ((void)0)
#else
#include <assert.h>
#endif

#ifndef _MSC_VER
#include <stdint.h>
#else
#if _MSC_VER >= 1600   /* MSVC 2010 or higher */
#include <stdint.h>
#else
typedef signed char int8_t;           // 8-bit signed integer
typedef unsigned char uint8_t;        // 8-bit unsigned integer
typedef signed short int16_t;         // 16-bit signed integer
typedef unsigned short uint16_t;      // 16-bit unsigned integer
typedef signed int int32_t;           // 32-bit signed integer
typedef unsigned int uint32_t;        // 32-bit unsigned integer
typedef signed long long int64_t;     // 64-bit signed integer
typedef unsigned long long uint64_t;  // 64-bit unsigned integer
#endif
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#ifdef  _MSC_VER
// This macro is used to handle LIB_EXPORT of function and variable names in lieu
// of a .def file. Visual Studio requires that functions be explicity exported and
// imported.
#   define LIB_EXPORT __declspec(dllexport) // VS compatible version
#   define LIB_IMPORT __declspec(dllimport)
// This is defined to indicate a function that does not return. Microsoft compilers
// do not support the _Noretrun function parameter.
#   define NORETURN  __declspec(noreturn)
#   define INLINE  __inline
#endif // _MSC_VER

#ifndef true
#define true (1)
#endif

#ifndef false
#define false (0)
#endif

#ifndef YES
#define YES (1)
#endif

#ifndef NO
#define NO  (0)
#endif

#define WORD_ALIGN(x) ((x & 0x3) ? ((x >> 2) + 1) << 2 : x)
#define HOST_IS_LITTLE_ENDIAN  true
#define HOST_IS_BIG_ENDIAN     false

#ifndef NDEBUG

extern uint8_t dbgCONFIGUREME;
extern uint8_t dbgINIT;
extern uint8_t dbgNET;
extern uint8_t dbgTARGET_CRYPTO;
extern uint8_t dbgTARGET_NVRAM;
extern uint8_t dbgTARGET_UTIL;

#endif

#define inline __inline

// Main method allows argc, argv
#define MAIN_ALLOWS_ARGS

#ifdef ALL_SYMBOLS
# define    static
#endif
#endif
