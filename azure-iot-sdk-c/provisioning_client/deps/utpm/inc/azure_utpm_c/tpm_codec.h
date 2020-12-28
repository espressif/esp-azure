// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TPM_CODEC_H
#define TPM_CODEC_H

#ifdef __cplusplus
#include <cstddef>
extern "C" {
#else
#include <stddef.h>
#endif /* __cplusplus */

#include "Tpm.h"
#include "tpm_comm.h"
#include "umock_c/umock_c_prod.h"

// TSS status codes

typedef enum
{
    TSS_SUCCESS = 0,
    TSS_E_NOT_IMPL = 0x8000,
    TSS_E_INVALID_PARAM,
    TSS_E_SOCK_INIT,
    TSS_E_SOCK_SHUTDOWN,
    TSS_E_TPM_CONNECT,
    TSS_E_TPM_SIM_STARTUP,
    TSS_E_TPM_SIM_INCOMPAT_VER,

    // TPM communication failure
    TSS_E_COMM = 0x80280100,
    TSS_E_TPM_TRANSACTION = TSS_E_COMM + 0x0001,
    TSS_E_TPM_SIM_BAD_ACK = TSS_E_COMM + 0x0002,
    TSS_E_BAD_RESPONSE = TSS_E_COMM + 0x0010,
    TSS_E_BAD_RESPONSE_LEN = TSS_E_COMM + 0x0011
}
TSS_STATUS;

// TPM Device management
typedef enum
{
    // Flags corresponding to the TpmEndPointInfo values used by the TPM simulator
    TSS_TpmPlatformAvailable = 0x01,
    TSS_TpmUsesTbs = 0x02,
    TSS_TpmInRawMode = 0x04,
    TSS_TpmSupportsPP = 0x08,

    // TPM connection type. Flags are mutually exclusive for better error checking
    TSS_SocketConn = 0x1000,
    TSS_TbsConn = 0x2000
}
TSS_TPM_CONN_INFO;

typedef struct
{
    // A set of TSS_TPM_CONN_INFO flags
    UINT32            TpmInfo;

    // Handle to the connection to the underlying TPM device
    //TSS_TPM_CONN_HANDLE TpmConnHandle;
    TPM_COMM_HANDLE tpm_comm_handle;

    // Raw response code returned by the last command executed by the given TPM device
    TPM_RC              LastRawResponse;

    const char* comms_endpoint;
}
TSS_DEVICE;

// TSS extensions of the TPM 2.0 command interafce
typedef struct
{
    TPMS_AUTH_COMMAND   SessIn;
    TPMS_AUTH_RESPONSE  SessOut;
}
TSS_SESSION;

MOCKABLE_FUNCTION(, TPM_RC, TSS_CreatePwAuthSession, TPM2B_AUTH*, authValue, TSS_SESSION*, session);

MOCKABLE_FUNCTION(, TPM_RC, TSS_StartAuthSession, TSS_DEVICE*, tpm, TPM_SE, sessionType, TPMI_ALG_HASH, authHash, TPMA_SESSION, sessAttrs, TSS_SESSION*, session);

MOCKABLE_FUNCTION(, UINT32, SignData, TSS_DEVICE*, tpm, TSS_SESSION*, sess, BYTE*, tokenData, UINT32, tokenSize, BYTE*, signatureBuffer, UINT32, sigBufSize);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_SequenceUpdate, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, sequenceHandle, TPM2B_MAX_BUFFER*, buffer);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_Sign, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, keyHandle, TPM2B_DIGEST*, digest, TPMT_SIG_SCHEME*, inScheme, TPMT_TK_HASHCHECK*, validation, TPMT_SIGNATURE*, signature);

MOCKABLE_FUNCTION(, TPM_RC, TSS_StartHmacAuthSession, TSS_DEVICE*, tpm, TPM_SE, sessionType, TPMI_ALG_HASH, authHash, TPMA_SESSION, sessAttrs, TSS_SESSION*, session);

MOCKABLE_FUNCTION(, TPM_RC, TSS_CreatePrimary, TSS_DEVICE*, tpm, TSS_SESSION*, sess, TPM_HANDLE, hierarchy, TPM2B_PUBLIC*, inPub, TPM_HANDLE*, outHandle, TPM2B_PUBLIC*, outPub);

MOCKABLE_FUNCTION(, TPM_RC, TSS_Create, TSS_DEVICE*, tpm, TSS_SESSION*, sess, TPM_HANDLE, parent, TPM2B_SENSITIVE_CREATE*, sensCreate, TPM2B_PUBLIC*, inPub, TPM2B_PRIVATE*, outPriv, TPM2B_PUBLIC*, outPub);

MOCKABLE_FUNCTION(, UINT32, TSS_GetTpmProperty, TSS_DEVICE*, tpm, TPM_PT, prop);

MOCKABLE_FUNCTION(, TPM_HANDLE, TSS_CreatePersistentKey, TSS_DEVICE*, tpm_device, TPM_HANDLE, request_handle, TSS_SESSION*, sess, TPMI_DH_OBJECT, hierarchy, TPM2B_PUBLIC*, inPub, TPM2B_PUBLIC*, outPub);

TPM_RC TSS_Hash(
    TSS_DEVICE             *tpm,                // IN/OUT
    BYTE                   *data,               // IN
    UINT32                  dataSize,           // IN
    TPMI_ALG_HASH           hashAlg,            // IN
    TPM2B_DIGEST           *outHash             // OUT
);

MOCKABLE_FUNCTION(, TPM_RC, TSS_HMAC, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, handle, BYTE*, data, UINT32, dataSize, TPM2B_DIGEST*, outHMAC);

TPM_RC TSS_SequenceComplete(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          sequenceHandle,     // IN
    BYTE                   *data,               // IN
    UINT32                  dataSize,           // IN
    TPM2B_DIGEST           *result              // OUT
);

TPM_RC TSS_SequenceUpdate(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          sequenceHandle,     // IN
    BYTE                   *data,               // IN
    UINT32                  dataSize            // IN
);

TPM_RC TSS_Sign(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          keyHandle,          // IN
    TPM2B_DIGEST           *digest,             // IN
    TPMT_SIGNATURE         *signature           // OUT
);

MOCKABLE_FUNCTION(, TPM_RC, TSS_PolicySecret, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_ENTITY, authHandle, TSS_SESSION*, policySession, TPM2B_NONCE*, nonceTPM, INT32, expiration);

// Represents fields of the TPMA_OBJECT bit field
typedef enum _OBJECT_ATTR
{
    FixedTPM = 0x2,
    StClear = 0x4,
    FixedParent = 0x10,
    SensitiveDataOrigin = 0x20,
    UserWithAuth = 0x40,
    AdminWithPolicy = 0x80,
    NoDA = 0x400,
    EncryptedDuplication = 0x800,
    Restricted = 0x10000,
    Decrypt = 0x20000,
    Sign = 0x40000,
    Encrypt = 0x40000
} OBJECT_ATTR;

MOCKABLE_FUNCTION(, TPMA_OBJECT, ToTpmaObject, UINT32, attrs);

MOCKABLE_FUNCTION(, TPM_RC, Initialize_TPM_Codec, TSS_DEVICE*, tpm);

MOCKABLE_FUNCTION(, void, Deinit_TPM_Codec, TSS_DEVICE*, tpm);

// TPM 2.0 command interafce
MOCKABLE_FUNCTION(, TPM_RC, TPM2_ActivateCredential, TSS_DEVICE*, tpm, TSS_SESSION*, activateSess, TSS_SESSION*, keySess, TPMI_DH_OBJECT, activateHandle, TPMI_DH_OBJECT, keyHandle, TPM2B_ID_OBJECT*, credentialBlob, TPM2B_ENCRYPTED_SECRET*, secret, TPM2B_DIGEST*, certInfo);

TPM_RC TPM2_Create(
    TSS_DEVICE               *tpm,              // IN/OUT
    TSS_SESSION              *session,          // IN/OUT
    TPMI_DH_OBJECT            parentHandle,     // IN
    TPM2B_SENSITIVE_CREATE   *inSensitive,      // IN
    TPM2B_PUBLIC             *inPublic,         // IN
    TPM2B_DATA               *outsideInfo,      // IN
    TPML_PCR_SELECTION       *creationPCR,      // IN
    TPM2B_PRIVATE            *outPrivate,       // OUT
    TPM2B_PUBLIC             *outPublic,        // OUT
    TPM2B_CREATION_DATA      *creationData,     // OUT
    TPM2B_DIGEST             *creationHash,     // OUT
    TPMT_TK_CREATION         *creationTicket    // OUT
);

TPM_RC TPM2_CreatePrimary(
    TSS_DEVICE               *tpm,              // IN/OUT
    TSS_SESSION              *session,          // IN/OUT
    TPMI_DH_OBJECT            primaryHandle,    // IN
    TPM2B_SENSITIVE_CREATE   *inSensitive,      // IN
    TPM2B_PUBLIC             *inPublic,         // IN
    TPM2B_DATA               *outsideInfo,      // IN
    TPML_PCR_SELECTION       *creationPCR,      // IN
    TPM_HANDLE               *objectHandle,     // OUT
    TPM2B_PUBLIC             *outPublic,        // OUT
    TPM2B_CREATION_DATA      *creationData,     // OUT
    TPM2B_DIGEST             *creationHash,     // OUT
    TPMT_TK_CREATION         *creationTicket    // OUT
);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_EncryptDecrypt, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, keyHandle, TPMI_YES_NO, decrypt, TPM_ALG_ID, cipherMode, TPM2B_IV*, ivIn, TPM2B_MAX_BUFFER*, inData, TPM2B_MAX_BUFFER*, outData, TPM2B_IV*, ivOut);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_EvictControl, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_RH_PROVISION, auth, TPMI_DH_OBJECT, objectHandle, TPMI_DH_PERSISTENT, persistentHandle);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_FlushContext, TSS_DEVICE*, tpm, TPMI_DH_CONTEXT, flushHandle);

TPM_RC
TPM2_GetCapability(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM_CAP                 capability,         // IN
    UINT32                  property,           // IN
    UINT32                  propertyCount,      // IN
    TPMI_YES_NO            *moreData,           // OUT
    TPMS_CAPABILITY_DATA   *capabilityData      // OUT
);

TPM_RC
TPM2_Hash(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM2B_MAX_BUFFER       *data,               // IN
    TPMI_ALG_HASH           hashAlg,            // IN
    TPMI_RH_HIERARCHY       hierarchy,          // IN
    TPM2B_DIGEST           *outHash,            // OUT
    TPMT_TK_HASHCHECK      *validation          // OUT
);

TPM_RC
TPM2_HashSequenceStart(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM2B_AUTH             *auth,               // IN [opt]
    TPMI_ALG_HASH           hashAlg,            // IN
    TPMI_DH_OBJECT         *sequenceHandle      // OUT
);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_HMAC, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, handle, TPM2B_MAX_BUFFER*, buffer, TPMI_ALG_HASH, hashAlg, TPM2B_DIGEST*, outHMAC);

TPM_RC
TPM2_HMAC_Start(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          handle,             // IN
    TPM2B_AUTH             *auth,               // IN [opt]
    TPMI_ALG_HASH           hashAlg,            // IN
    TPMI_DH_OBJECT         *sequenceHandle      // OUT
);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_Import, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, parentHandle, TPM2B_DATA*, encryptionKey, TPM2B_PUBLIC*, objectPublic, TPM2B_PRIVATE*, duplicate, TPM2B_ENCRYPTED_SECRET*, inSymSeed, TPMT_SYM_DEF_OBJECT*, symmetricAlg, TPM2B_PRIVATE*, outPrivate);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_Load, TSS_DEVICE*, tpm, TSS_SESSION*, session, TPMI_DH_OBJECT, parentHandle, TPM2B_PRIVATE*, inPrivate, TPM2B_PUBLIC*, inPublic, TPM_HANDLE*, objectHandle, TPM2B_NAME*, name);

TPM_RC
TPM2_PolicySecret(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_ENTITY          authHandle,         // IN
    TPMI_SH_POLICY          policySession,      // IN
    TPM2B_NONCE            *nonceTPM,           // IN [opt]
    TPM2B_DIGEST           *cpHashA,            // IN [opt]
    TPM2B_NONCE            *policyRef,          // IN [opt]
    INT32                   expiration,         // IN [opt]
    TPM2B_TIMEOUT          *timeout,            // OUT
    TPMT_TK_AUTH           *policyTicket        // OUT [opt]
);

MOCKABLE_FUNCTION(, TPM_RC, TPM2_ReadPublic, TSS_DEVICE*, tpm, TPMI_DH_OBJECT, objectHandle, TPM2B_PUBLIC*, outPublic, TPM2B_NAME*, name, TPM2B_NAME*, qualifiedName);

TPM_RC
TPM2_StartAuthSession(
    TSS_DEVICE               *tpm,              // IN/OUT
    TPMI_DH_OBJECT            tpmKey,           // IN
    TPMI_DH_ENTITY            bind,             // IN
    TPM2B_NONCE              *nonceCaller,      // IN
    TPM2B_ENCRYPTED_SECRET   *encryptedSalt,    // IN
    TPM_SE                    sessionType,      // IN
    TPMT_SYM_DEF             *symmetric,        // IN
    TPMI_ALG_HASH             authHash,         // IN
    TPMI_SH_AUTH_SESSION     *sessionHandle,    // OUT
    TPM2B_NONCE              *nonceTPM          // OUT
);

TPM_RC
TPM2_Startup(
    TSS_DEVICE *tpm,                // IN/OUT
    TPM_SU      startupType         // IN
);


//
// TPM commands handling
//

UINT32
TSS_BuildCommand(
    TPM_CC           cmdCode,       // IN: Command code
    TPM_HANDLE      *handles,       // IN (opt): Array of handles used by the command
    INT32            numHandles,    // IN: Number of handles in 'handles'
    TSS_SESSION    **sessions,      // IN (opt): Array of sessions
    INT32            numSessions,   // IN: Number of sessions in 'sessions'
    BYTE            *params,        // IN (opt): Marshaled command parameters
    INT32            paramsSize,    // IN: Size of 'params' in bytes
    BYTE            *cmdBuffer,     // OUT: Command buffer ready for sending to TPM
    INT32            bufCapacity    // IN: Capacity of 'cmdBuffer' in bytes
);

TSS_STATUS
TSS_SendCommand(
    TSS_DEVICE  *tpm,               // IN: TPM device
    BYTE        *cmdBuffer,         // IN: Command buffer
    INT32        cmdSize,           // IN: Size of 'cmdBuffer' in bytes
    BYTE        *respBuffer,        // IN: Buffer for response to receive from TPM
    INT32       *respSize           // IN/OUT: IN: Capacity of 'respBuffer' in bytes
                                    //        OUT: Size of data in 'respBuffer'
);

UINT16
TSS_GetDigestSize(
    TPM_ALG_ID  hashAlg     // IN: hash algorithm to look up
);

void TSS_RandomBytes(
    BYTE    *buf,           // OUT: buffer to fill with random bytes
    int      bufSize        // Number of random bytes to generate
);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // TPM_CODEC_H