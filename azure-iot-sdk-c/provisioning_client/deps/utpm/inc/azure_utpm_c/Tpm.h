// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Root header file for building any TPM.lib code

#ifndef     _TPM_H_
#define     _TPM_H_

#include "Implementation.h"


#include "GpMacros.h"
#include "Capabilities.h"
#include "TpmTypes.h"
#include "TpmError.h"

void
TpmFail(
#ifndef NO_FAIL_TRACE
    const char      *function,
    int              line,
#endif
    int              code
    );

#endif // _TPM_H_
