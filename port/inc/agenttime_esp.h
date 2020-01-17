// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//This file pulls in OS-specific header files to allow compilation of socket_async.c under
// most OS's except for Windows.

// For ESP platform lwIP systems which use the ESP-IDF's non-standard lwIP include structure
// Tested with:
// ESP platform

#ifndef AGENTTIME_ESP_H
#define AGENTTIME_ESP_H

#include <time.h>

void initialize_sntp(void);
void finalize_sntp(void);
time_t sntp_get_current_timestamp();

#endif // AGENTTIME_ESP_H
