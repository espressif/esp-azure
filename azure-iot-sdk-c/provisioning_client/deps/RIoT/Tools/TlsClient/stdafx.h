// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/tls1.h>
#include <openssl/x509v3.h>

// just need this for Sleep() - a debugging aid
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#ifndef HOST_NAME
# define HOST_NAME "localhost"
#endif

#ifndef HOST_PORT
# define HOST_PORT "5556"
#endif

#ifndef HOST_RESOURCE
# define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"
#endif

#  define ASSERT(x) { \
  if(!(x)) { \
    fprintf(stderr, "Assertion: %s: function %s, line %d\n", (char*)(__FILE__), (char*)(__func__), (int)__LINE__); \
  } \
}


// TODO: reference additional headers your program requires here
