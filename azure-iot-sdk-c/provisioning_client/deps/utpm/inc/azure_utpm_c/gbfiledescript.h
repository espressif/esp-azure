// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef GBFILEDESCRIPT_H
#define GBFILEDESCRIPT_H

#ifndef ssize_t
#define ssize_t int
#endif

#include "umock_c/umock_c_prod.h"

#ifdef __cplusplus
#include <cstddef>
#include <cstdlib>
extern "C"
{
#else
#include <stddef.h>
#include <stdlib.h>
#endif

#ifdef WIN32
#define F_OK    1
#endif

#if defined(GB_DEBUG_FILEDESCRIPT)

MOCKABLE_FUNCTION(, ssize_t, gbfiledesc_write, int, fd, const void*, buff, size_t, count);
MOCKABLE_FUNCTION(, ssize_t, gbfiledesc_read, int, fd, void*, buf, size_t, len);
MOCKABLE_FUNCTION(, int, gbfiledesc_access, const char*, s, int, mode);
MOCKABLE_FUNCTION(, int, gbfiledesc_close, int, fd);
MOCKABLE_FUNCTION(, int, gbfiledesc_open, const char*, path, int, flags);

#define open  gbfiledesc_open
#define write gbfiledesc_write
#define read gbfiledesc_read
#define access gbfiledesc_access
#define close gbfiledesc_close

#endif /* GB_DEBUG_FILEDESCRIPT */

#ifdef __cplusplus
}
#endif

#endif // GBFILEDESCRIPT_H
