// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef WIN32
#include <Windows.h>
#include <basetsd.h>
#else // WIN32
#include <sys/stat.h>
#include <fcntl.h>
#ifdef __APPLE__
#include <string.h>
#endif // __APPLE__
#include <unistd.h>
#endif // WIN32
#include "azure_utpm_c/gbfiledescript.h"

ssize_t gbfiledesc_write(int fd, const void* tpm_bytes, size_t count)
{
#ifdef WIN32
    (void)fd;
    (void)tpm_bytes;
    (void)count;
    return 0;
#else
    return write(fd, tpm_bytes, count);
#endif
}

ssize_t gbfiledesc_read(int fd, unsigned char* tpm_bytes, uint32_t count)
{
#ifdef WIN32
    (void)fd;
    (void)tpm_bytes;
    (void)count;
    return 0;
#else
    return read(fd, tpm_bytes, count);
#endif
}

int gbfiledesc_access(const char* path, int mode)
{
#ifdef WIN32
    (void)path;
    (void)mode;
    return 0;
#else
    return access(path, mode);
#endif
}

int gbfiledesc_close(int fd)
{
#ifdef WIN32
    (void)fd;
    return 0;
#else
    return close(fd);
#endif
}

int gbfiledesc_open(const char* path, int flags)
{
#ifdef WIN32
    (void)path;
    (void)flags;
    return 0;
#else
    return open(path, flags);
#endif
}
