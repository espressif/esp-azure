// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file contains the build switches. This contains switches for multiple
// versions of the crypto-library so some may not apply to your environment.
//
// The switches are guarded so that they can either be set on the command line or
// set here.

#ifndef _TPM_BUILD_SWITCHES_H_
#define _TPM_BUILD_SWITCHES_H_

// Many of the #defines are guarded so that they can be set on the command line
// without causing consternation in the compiler.
#ifndef INLINE_FUNCTIONS
//#  define INLINE_FUNCTIONS
#endif

// Don't move this include ahead of the INLINE_FUNCTIONS definition.
#include "CompilerDependencies.h"

// This definition is required for the re-factored code
#define USE_BN_ECC_DATA

// Comment these out as needed
#ifndef SIMULATION
#  define SIMULATION
#endif

// Define this to run the function that checks the format compatibility for the
// chosen big number math library. Not all ports use this.
#if !defined LIBRARY_COMPATIBILITY_CHECK && defined SIMULATION
#   define LIBRARY_COMPATABILITY_CHECK
#endif


#ifndef FIPS_COMPLIANT
//#  define FIPS_COMPLIANT
#endif

// Definition to allow alternate behavior for non-orderly startup. If there is a
// chance that the TPM could not update 'failedTries'
#ifndef USE_DA_USED
#   define USE_DA_USED
#endif

// Define TABLE_DRIVEN_DISPATCH to use tables rather than case statements
// for command dispatch and handle unmarshaling
#ifndef TABLE_DRIVEN_DISPATCH
#  define TABLE_DRIVEN_DISPATCH
#endif

// This switch is used to enable the self-test capability in AlgorithmTests.c
#ifndef SELF_TEST
#define SELF_TEST
#endif

// Enable the generation of RSA primes using a sieve.
#ifndef RSA_KEY_SIEVE
#  define RSA_KEY_SIEVE
#endif

// Enable the instrumentation of the sieve process. This is used to tune the sieve
// variables.
#if !defined RSA_INSTRUMENT && defined RSA_KEY_SIEVE && defined SIMULATION
//#define RSA_INSTRUMENT
#endif

#if defined RSA_KEY_SIEVE && !defined NDEBUG && !defined RSA_INSTRUMENT
//# define RSA_INSTRUMENT
#endif

// This switch enables the RNG state save and restore
#ifndef _DRBG_STATE_SAVE
#  define _DRBG_STATE_SAVE        // Comment this out if no state save is wanted
#endif

// Switch added to support packed lists that leave out space associated with
// unimplemented commands. Comment this out to use linear lists.
// Note: if vendor specific commands are present, the associated list is always
// in compressed form.
#ifndef COMPRESSED_LISTS
#   define COMPRESSED_LISTS
#endif

// This switch indicates where clock epoch value should be stored. If this value
// defined, then it is assumed that the timer will change at any time so the
// nonce should be a random number kept in RAM. When it is not defined, then the
// timer only stops during power outages.
#ifndef CLOCK_STOPS
//#   define CLOCK_STOPS
#endif

//**********************************
// The switches in this group can only be enabled when running a simulation
#ifdef SIMULATION
// Enables use of the key cache
#   ifndef USE_RSA_KEY_CACHE
#       define USE_RSA_KEY_CACHE
#   endif
#   if defined USE_RSA_KEY_CACHE && !defined USE_KEY_CACHE_FILE
#       define USE_KEY_CACHE_FILE
#   endif
#   if !defined NDEBUG && !defined USE_DEBUG_RNG
// This provides fixed seeding of the RNG when doing debug on a simulator. This
// should allow consistent results on test runs as long as the input parameters
// to the functions remains the same.
#       define USE_DEBUG_RNG
#   endif
#else
#   undef USE_RSA_KEY_CACHE
#   undef USE_KEY_CACHE_FILE
#   undef USE_DEBUG_RNG
#   undef RSA_INSTRUMENT
#endif  // SIMULATION

#ifndef NDEBUG

// In some cases, the relationship between two values may be dependent
// on things that change based on various selections like the chosen cryptographic
// libraries. It is possible that these selections will result in incompatible
// settings. These are often detectable by the compiler but it isn't always
// possible to do the check in the preprocessor code. For example, when the
// check requires use of 'sizeof()' then the preprocessor can't do the comparison.
// For these cases, we include a special macro that, depending on the compiler
// will generate a warning to indicate if the check always passes or always fails
// because it involves fixed constants. To run these checks, define COMPILER_CHECKS.
#ifndef COMPILER_CHECKS
//#   define COMPILER_CHECKS
#endif

// Some of the values (such as sizes) are the result of different options set in
// Implementation.h. The combination might not be consistent. A function is defined
// (TpmSizeChecks()) that is used to verify the sizes at run time. To enable the
// function, define this parameter.
#ifndef RUNTIME_SIZE_CHECKS
#define RUNTIME_SIZE_CHECKS
#endif

// If doing debug, can set the DRBG to print out the intermediate test values.
// Before enabling this, make sure that the dbgDumpMemBlock() function
// has been added someplace (preferably, somewhere in CryptRand.c)
#ifndef DRBG_DEBUG_PRINT
//#  define DRBG_DEBUG_PRINT
#endif

// If an assertion event it not going to produce any trace information (function and
// line number) then define NO_FAIL_TRACE
#ifndef NO_FAIL_TRACE
#   define NO_FAIL_TRACE
#endif

#endif // NDEBUG

// If the implementation is going to give lockout time credit for time up to the
// last orderly shutdown, then uncomment this variable
#ifndef ACCUMULATE_SELF_HEAL_TIMER
#define ACCUMULATE_SELF_HEAL_TIMER
#endif // ACCUMULATE_SELF_HEAL_TIMER

#define EXPIRATION_BIT                  ((UINT64)1 << 63)

#endif // _TPM_BUILD_SWITCHES_H_