// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file contains the build switches. This contains switches for multiple
// versions of the crypto-library so some may not apply to your environment.
//

#ifndef _COMPILER_DEPENDENCIES_H_
#define _COMPILER_DEPENDENCIES_H_

#ifdef GCC
#   undef _MSC_VER
#   undef WIN32
#endif

// If in-line functions are not being used, define INLINE as null. If
// INLINE_FUNCTIONS is defined, then need to define INLINE for each compiler.
#ifndef INLINE_FUNCTIONS
#   define INLINE
#endif

#ifdef _MSC_VER
// These definitions are for the Microsoft compiler

// Endian conversion for aligned structures
#   define REVERSE_ENDIAN_16(_Number) _byteswap_ushort(_Number)
#   define REVERSE_ENDIAN_32(_Number) _byteswap_ulong(_Number)
#   define REVERSE_ENDIAN_64(_Number) _byteswap_uint64(_Number)
// Handling of INLINE macro
#   ifdef INLINE_FUNCTIONS
#    define INLINE   static __inline
#   endif

// Avoid compiler warning for in line of stdio (or not)
//#define _NO_CRT_STDIO_INLINE

// This macro is used to handle LIB_EXPORT of function and variable names in lieu
// of a .def file. Visual Studio requires that functions be explicitly exported and
// imported.
#   define LIB_EXPORT __declspec(dllexport) // VS compatible version
#   define LIB_IMPORT __declspec(dllimport)

// This is defined to indicate a function that does not return. Microsoft compilers
// do not support the _Noretrun function parameter.
#   define NORETURN  __declspec(noreturn)
#   if _MSC_VER >= 1400     // SAL processing when needed
#       include <sal.h>
#   endif

#   ifdef _WIN64
#       define _INTPTR 2
#    else
#       define _INTPTR 1
#    endif


#define NOT_REFERENCED(x)   (x)

// Lower the compiler error warning for system include
// files. They tend not to be that clean and there is no
// reason to sort through all the spurious errors that they
// generate when the normal error level is set to /Wall
#   define _REDUCE_WARNING_LEVEL_(n)                    \
__pragma(warning(push, n))
// Restore the compiler warning level
#   define _NORMAL_WARNING_LEVEL_                       \
__pragma(warning(pop))
#   include <stdint.h>
#endif

#ifndef _MSC_VER
#   define WINAPI
#   define __pragama(x)
#   define REVERSE_ENDIAN_16(_Number) __builtin_bswap16(_Number)
#   define REVERSE_ENDIAN_32(_Number) __builtin_bswap32(_Number)
#   define REVERSE_ENDIAN_64(_Number) __builtin_bswap64(_Number)
#   ifdef INLINE_FUNCTIONS
#   define INLINE static inline
#endif

#if defined(__GNUC__)
#   define NORETURN                     __attribute__((noreturn))
#   include <stdint.h>
#  else
#   define NORETURN
#  endif
#   define LIB_EXPORT
#   define LIB_IMPORT
#   define _REDUCE_WARNING_LEVEL_(n)
#   define _NORMAL_WARNING_LEVEL_
#   define  NOT_REFERENCED(x) (x = x)
#endif

#ifdef _POSIX_
typedef int SOCKET;
#endif


#endif // _COMPILER_DEPENDENCIES_H_