// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stdbool.h>
#include "umock_c/umock_c_prod.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/buffer_.h"

#include "azure_utpm_c/tpm_codec.h"

#include <stdio.h>
#include <stdarg.h>

#include "azure_utpm_c/Tpm.h"
#include "azure_utpm_c/Memory_fp.h"
#include "azure_utpm_c/Marshal_fp.h"

#define MAX_COMMAND_BUFFER      4096
#define MAX_RESPONSE_BUFFER     MAX_COMMAND_BUFFER
#define USE_HMAC_SEQ            0
#define TSS_BAD_PROPERTY        ((UINT32)-1)

// Forward Declarations
static UINT16              NullSize = 0;
static TPMT_SYM_DEF        NullSymDef = { TPM_ALG_NULL , {0}, { TPM_ALG_NULL } };
static TPMT_SYM_DEF_OBJECT NullSymDefObject = { TPM_ALG_NULL, {0}, {TPM_ALG_NULL} };
static TPMT_SIG_SCHEME     NullSigScheme = { TPM_ALG_NULL, { {TPM_ALG_NULL} } };
static TPMT_TK_HASHCHECK   NullHashTk = { TPM_ST_HASHCHECK, TPM_RH_NULL, {{0}} };
static const UINT32 DPS_ID_KEY_HANDLE = HR_PERSISTENT | 0x00000100;

typedef const char* (*ErrCodeMsgFnPtr)(UINT32 msgID);

static const char* TSS_StatusValueName(UINT32 rc);

typedef struct
{
    // IN: Size of parameters buffer (bytes)
    UINT32      ParamSize;

    // IN: Parameters buffer (in TPM representation)
    BYTE        ParamBuffer[MAX_COMMAND_BUFFER];

    // OUT: Comamnd buffer size (bytes)
    UINT32      CmdSize;

    // OUT: Comamnd buffer (in TPM representation)
    BYTE        CmdBuffer[MAX_COMMAND_BUFFER];

    // OUT: Total size of the response buffer (bytes)
    UINT32      RespSize;

    // OUT: Response buffer data
    BYTE        RespBuffer[MAX_RESPONSE_BUFFER];

    // OUT: Number of bytes left not unmarshaled in the response buffer
    //      (params and sessions)
    UINT32      RespBytesLeft;

    // OUT: Pointer to the not unmarshaled part of the response buffer
    BYTE       *RespBufPtr;

    // OUT: Unmarshaled handle returned by the command
    TPM_HANDLE  RetHandle;

    // OUT: Unmarshaled size of response parameters in the response buffer (bytes)
    UINT32      RespParamSize;
} TSS_CMD_CONTEXT;

TPM_RC
TSS_DispatchCmd(
    TSS_DEVICE      *tpm,           // IN
    TPM_CC           cmdCode,       // IN: Command code
    TPM_HANDLE      *handles,       // IN (opt): Array of handles used by the command
    INT32            numHandles,    // IN: Number of handles in 'handles'
    TSS_SESSION    **sessions,      // IN (opt): Array of sessions
    INT32            numSessions,   // IN: Number of sessions in 'sessions'
    TSS_CMD_CONTEXT *cmdCtx         // IN/OUT: On input contains initialized parameter buffer
                                    //     On output contains complete command and response buffers
);

static TSS_CMD_CONTEXT  CmdCtx;

#define BEGIN_CMD()  \
    TPM_RC           cmdResult = TPM_RC_SUCCESS;                            \
    TSS_CMD_CONTEXT *cmdCtx = &CmdCtx;                                      \
    INT32            sizeParamBuf = sizeof(cmdCtx->ParamBuffer);            \
    BYTE            *paramBuf = cmdCtx->ParamBuffer;                        \
    (void)sizeParamBuf;                                                     \
    (void)paramBuf;                                                         \
    cmdCtx->ParamSize = 0

#define END_CMD()  \
    return cmdResult

#define DISPATCH_CMD(cmdName, pHandles, numHandles, pSessions, numSessions) \
    cmdResult = TSS_DispatchCmd(tpm, TPM_CC_##cmdName,                          \
                                pHandles, numHandles, pSessions, numSessions,   \
                                cmdCtx);                                        \
    if (cmdResult != TPM_RC_SUCCESS)                                            \
        return cmdResult;

// Standard TPM marshaling macros forcefully cast their first argument to the
// corresponding pointer type, which hides potential errors when a value type is used
// instead of a pointer. TSS_CHECK_PTR is used to trigger a compiler warning in such
// cases.
#define TSS_CHECK_PTR(ptr)      { void* p = ptr; (void)p; }


#define TSS_MARSHAL(Type, pValue) \
{                                                                           \
    TSS_CHECK_PTR(pValue)                                                   \
    cmdCtx->ParamSize += Type##_Marshal(pValue, &paramBuf, &sizeParamBuf);  \
}

#define TSS_MARSHAL_OPT2B(Type, pValue) \
    if (pValue != NULL)                 \
        TSS_MARSHAL(Type, pValue)       \
    else                                \
        TSS_MARSHAL(UINT16, &NullSize)

#define TSS_UNMARSHAL(Type, pValue) \
{                                                                                   \
    if (   Type##_Unmarshal(pValue, &cmdCtx->RespBufPtr, (INT32*)&cmdCtx->RespBytesLeft)    \
        != TPM_RC_SUCCESS)                                                          \
        return TPM_RC_INSUFFICIENT;                                                 \
}

#define TSS_UNMARSHAL_OPT(Type, pValue) \
    if (!(pValue)) {                        \
        Type  val;                          \
        TSS_UNMARSHAL(Type, &val);          \
    }                                       \
    else                                    \
        TSS_UNMARSHAL(Type, pValue)

#define TSS_UNMARSHAL_FLAGGED(Type, pValue) \
{                                                                                       \
    if (   Type##_Unmarshal(pValue, &cmdCtx->RespBufPtr, (INT32*)&cmdCtx->RespBytesLeft, TRUE)  \
        != TPM_RC_SUCCESS)                                                              \
        return TPM_RC_INSUFFICIENT;                                                     \
}

#define TSS_COPY2B(dst2b, src2b) \
    MemoryCopy2B(&(dst2b).b, &(src2b).b, sizeof((dst2b).t.buffer))

#define CHECK_CMD_RESULT2(rc, errMsg, msgArg1, msgArg2) \
    if (rc != TPM_RC_SUCCESS)                           \
    {                                                   \
        goto end;                                       \
    }

#define CHECK_CMD_RESULT1(rc, errMsg, msgArg1) \
    CHECK_CMD_RESULT2(rc, errMsg, msgArg1, "")

#define CHECK_CMD_RESULT(rc, errMsg) \
    CHECK_CMD_RESULT1(rc, errMsg, "")

static bool IsCommMediumError(UINT32 code)
{
    // TBS or TPMSim protocol error
    return (code & 0xFFFF0000) == 0x80280000;
}

/*static void ClearPersistentPrimary(TSS_DEVICE *tpm, TPM_HANDLE hPers, const char* PrimaryRole)
{
    bool            res = false;
    TPM_RC          rc;
    TPM2B_PUBLIC    pub;
    TPM2B_NAME      name, qName;

    rc = TPM2_ReadPublic(tpm, hPers, &pub, &name, &qName);
    if (rc == TPM_RC_SUCCESS)
    {
        rc = TPM2_EvictControl(tpm, &NullPwSession, TPM_RH_OWNER, hPers, hPers);
        CHECK_CMD_RESULT1(rc, "TPM2_EvictControl for %s failed", PrimaryRole);

        Print("Successfully deleted persistent %s 0x%08X\r\n", PrimaryRole, hPers);
    }
    else if (rc == TPM_RC_HANDLE)
    {
        Print("%s 0x%08X does not exist\r\n", PrimaryRole, hPers);
    }
    else
        TSS_PrintError("Unexpected failure of TPM2_ReadPublic for %s 0x%08X", rc, PrimaryRole, hPers);

end:
}*/

static TPM_RC CleanResponseCode(TPM_RC rawResponse)
{
    if (IsCommMediumError(rawResponse))
    {
        LogError("invalid rawResponse (0x%0x)", rawResponse);
        return rawResponse;
    }

    UINT32 mask = rawResponse & RC_FMT1 ? RC_FMT1 | 0x3F : TPM_RC_NOT_USED; // RC_WARN | RC_VER1 | 0x7F
    return rawResponse & mask;
}

TPM_HANDLE TSS_CreatePersistentKey(TSS_DEVICE* tpm_device, TPM_HANDLE request_handle, TSS_SESSION* sess, TPMI_DH_OBJECT hierarchy, TPM2B_PUBLIC* inPub, TPM2B_PUBLIC* outPub)
{
    TPM_HANDLE result;
    TPM_RC tpm_result;
    TPM2B_NAME name;
    TPM2B_NAME qName;

    tpm_result = TPM2_ReadPublic(tpm_device, request_handle, outPub, &name, &qName);
    if (tpm_result == TPM_RC_SUCCESS)
    {
        result = request_handle;
    }
    else if (tpm_result != TPM_RC_HANDLE)
    {
        LogError("Failed calling TPM2_ReadPublic 0x%x", tpm_result);
        result = 0;
    }
    else
    {
        if ((tpm_result = TSS_CreatePrimary(tpm_device, sess, hierarchy, inPub, &result, outPub)) != TPM_RC_SUCCESS)
        {
            LogError("Failed calling TSS_CreatePrimary 0x%x", tpm_result);
            result = 0;
        }
        else
        {
            if ((tpm_result = TPM2_EvictControl(tpm_device, sess, TPM_RH_OWNER, result, request_handle)) != TPM_RC_SUCCESS)
            {
                LogError("Failed calling TPM2_EvictControl 0x%x", tpm_result);
                result = 0;
            }
            else if ((tpm_result = TPM2_FlushContext(tpm_device, result)) != TPM_RC_SUCCESS)
            {
                LogError("Failed calling TPM2_FlushContext 0x%x", tpm_result);
                result = 0;
            }
            else
            {
                result = request_handle;
            }
        }
    }
    return result;
}

TPM_RC Initialize_TPM_Codec(TSS_DEVICE* tpm)
{
    TPM_RC result;
    if (tpm == NULL)
    {
        LogError("Invalid parameter tpm is NULL");
        result = TPM_RC_FAILURE;
    }
    else if ( (tpm->tpm_comm_handle = tpm_comm_create(tpm->comms_endpoint)) == NULL)
    {
        LogError("creating tpm_comm object");
        result = TPM_RC_FAILURE;
    }
    else
    {
        TPM_COMM_TYPE comm_type = tpm_comm_get_type(tpm->tpm_comm_handle);
        if (comm_type == TPM_COMM_TYPE_EMULATOR)
        {
            result = TPM2_Startup(tpm, TPM_SU_CLEAR);
            if (result != TPM_RC_SUCCESS && result != TPM_RC_INITIALIZE)
            {
                LogError("calling TPM2_Startup %s", TSS_StatusValueName(result) );
                tpm_comm_destroy(tpm->tpm_comm_handle);
            }
            else
            {
                result = TPM_RC_SUCCESS;
            }
        }
        else
        {
            result = TPM_RC_SUCCESS;
        }
        // Clear out from previous runs
        (void)TPM2_FlushContext(tpm, HR_POLICY_SESSION);
        (void)TPM2_FlushContext(tpm, HR_POLICY_SESSION | 1);
        (void)TPM2_FlushContext(tpm, HR_POLICY_SESSION | 2);
    }
    return result;
}

void Deinit_TPM_Codec(TSS_DEVICE* tpm)
{
    if (tpm != NULL)
    {
        tpm_comm_destroy(tpm->tpm_comm_handle);
    }
}

// In case of success returns the size of the signature. If the signature size is
// greater than sigBufCapacity, then the signature is not copied into signatureBuffer.
// If any of the TPM commands fails, returns 0, and tpm->LastRawResponse contains
// the response code from the failed command.
//
// NOTE: For now only HMAC signing is supported.
//
UINT32 SignData(TSS_DEVICE* tpm, TSS_SESSION* sess, BYTE* tokenData, UINT32 tokenSize, BYTE* signatureBuffer, UINT32 sigBufSize)
{
    UINT32 result;
    TPM_RC          rc;
    TPM2B_DIGEST    digest;
    TPM_ALG_ID      idKeyHashAlg = ALG_SHA256_VALUE;
    UINT32          sigSize = TSS_GetDigestSize(idKeyHashAlg); //32
    UINT32          MaxInputBuffer = 0;

    if (sigBufSize < sigSize)
    {
        LogError("Signature buffer size (%uz) is less than required size (%uz)", sigBufSize, sigSize);
        result = sigSize;
    }
    else
    {
        sigBufSize = 0;
        MaxInputBuffer = TSS_GetTpmProperty(tpm, TPM_PT_INPUT_BUFFER); // 1024
        if (tokenSize > MaxInputBuffer) // 68
        {
            TPMI_DH_OBJECT  hSeq = TPM_RH_NULL;
            BYTE           *curPos = tokenData;
            UINT32          bytesLeft = tokenSize;

            rc = TPM2_HMAC_Start(tpm, sess, DPS_ID_KEY_HANDLE, NULL, idKeyHashAlg, &hSeq);
            if (rc != TPM_RC_SUCCESS)
            {
                LogError("Failed to start HMAC sequence %s", TSS_StatusValueName(rc) );
                result = 0;
            }
            else
            {
                bool seq_complete = true;
                // Above condition 'if (tokenSize > MaxInputBuffer)' ensures that the first
                // iteration is always valid.
                do
                {
                    rc = TSS_SequenceUpdate(tpm, sess, hSeq, curPos, MaxInputBuffer);
                    if (rc != TPM_RC_SUCCESS)
                    {
                        LogError("Failed to update HMAC sequence %s", TSS_StatusValueName(rc));
                        seq_complete = false;
                        break;
                    }

                    bytesLeft -= MaxInputBuffer;
                    curPos += MaxInputBuffer;
                } while (bytesLeft > MaxInputBuffer);

                if (seq_complete)
                {
                    rc = TSS_SequenceComplete(tpm, sess, hSeq, curPos, bytesLeft, &digest);
                    if (rc != TPM_RC_SUCCESS)
                    {
                        LogError("Failed to complete HMAC sequence %s", TSS_StatusValueName(rc));
                        result = 0;
                    }
                    else
                    {
                        MemoryCopy(signatureBuffer, digest.t.buffer, sigSize);
                        sigBufSize = sigSize;
                        result = sigBufSize;
                    }
                }
                else
                {
                    result = 0;
                }
            }
        }
        else
        {
            rc = TSS_HMAC(tpm, sess, DPS_ID_KEY_HANDLE, tokenData, tokenSize, &digest);
            if (rc != TPM_RC_SUCCESS)
            {
                LogError("Hashing token data failed %s", TSS_StatusValueName(rc));
                result = 0;
            }
            else
            {
                MemoryCopy(signatureBuffer, digest.t.buffer, sigSize);
                sigBufSize = sigSize;
                result = sigBufSize;
            }
        }
    }
    return result;
}

TPM_RC TPM2_HMAC(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          handle,             // IN
    TPM2B_MAX_BUFFER       *buffer,             // IN
    TPMI_ALG_HASH           hashAlg,            // IN
    TPM2B_DIGEST           *outHMAC             // OUT
)
{
    TPM_RC result;
    if (tpm == NULL || session == NULL || buffer == NULL || outHMAC == NULL)
    {
        LogError("Invalid parameter specified tpm: %p, session: %p, buffer: %p, outHMAC: %p", tpm, session, buffer, outHMAC);
        result = TPM_RC_FAILURE;
    }
    else
    {
        result = TPM_RC_SUCCESS;
        BEGIN_CMD();
        TSS_MARSHAL_OPT2B(TPM2B_MAX_BUFFER, buffer);
        TSS_MARSHAL(TPMI_ALG_HASH, &hashAlg);
        DISPATCH_CMD(HMAC, &handle, 1, &session, 1);
        TSS_UNMARSHAL(TPM2B_DIGEST, outHMAC);
        END_CMD();
    }
    return result;
}

TPM_RC TSS_HMAC(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          handle,             // IN
    BYTE                   *data,               // IN
    UINT32                  dataSize,           // IN
    TPM2B_DIGEST           *outHMAC             // OUT
)
{
    TPM_RC result;
    if (dataSize > MAX_DIGEST_BUFFER)
    {
        LogError("Invalid data size specified %u", dataSize);
        result = TPM_RC_SIZE;
    }
    else if (tpm == NULL || session == NULL || data == NULL || outHMAC == NULL)
    {
        LogError("Invalid parameter specified tpm: %p, session: %p, data: %p, outHMAC: %p", tpm, session, data, outHMAC);
        result = TPM_RC_FAILURE;
    }
    else
    {
        TPM2B_MAX_BUFFER    dataBuf;
        dataBuf.b.size = (UINT16)dataSize;
        MemoryCopy(dataBuf.t.buffer, data, dataSize);
        result = TPM2_HMAC(tpm, session, handle, &dataBuf, TPM_ALG_NULL, outHMAC);
    }
    return result;
}

TPM_RC
TSS_Hash(
    TSS_DEVICE             *tpm,                // IN/OUT
    BYTE                   *data,               // IN
    UINT32                  dataSize,           // IN
    TPMI_ALG_HASH           hashAlg,            // IN
    TPM2B_DIGEST           *outHash             // OUT
)
{
    TPM2B_MAX_BUFFER    dataBuf;// = { (UINT16)dataSize };
    dataBuf.t.size = (UINT16)dataSize;

    if (dataSize > MAX_DIGEST_BUFFER)
        return TPM_RC_SIZE;
    MemoryCopy(dataBuf.t.buffer, data, dataSize);

    return TPM2_Hash(tpm, &dataBuf, hashAlg, TPM_RH_NULL, outHash, NULL);
}

TPM_RC
TSS_PolicySecret(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_ENTITY          authHandle,         // IN
    TSS_SESSION            *policySession,      // IN
    TPM2B_NONCE            *nonceTPM,           // IN
    INT32                   expiration          // IN
)
{
    TPM_RC result;
    TPM2B_TIMEOUT   timeout;
    if (session == NULL || policySession == NULL)
    {
        LogError("Invalid parameter specified policySession: %p session: %p", policySession, session);
        result = TPM_RC_FAILURE;
    }
    else
    {
        result = TPM2_PolicySecret(tpm, session, authHandle, policySession->SessIn.sessionHandle, nonceTPM, NULL, NULL, expiration, &timeout, NULL);
    }
    return result;
}

TPM_RC
TPM2_SequenceComplete(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          sequenceHandle,     // IN
    TPM2B_MAX_BUFFER       *buffer,             // IN
    TPMI_RH_HIERARCHY       hierarchy,          // IN [opt]
    TPM2B_DIGEST           *result,             // OUT
    TPMT_TK_HASHCHECK      *validation          // OUT [opt]
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_MAX_BUFFER, buffer);
    TSS_MARSHAL(TPMI_RH_HIERARCHY, &hierarchy);
    DISPATCH_CMD(SequenceComplete, &sequenceHandle, 1, &session, 1);
    TSS_UNMARSHAL(TPM2B_DIGEST, result);
    TSS_UNMARSHAL_OPT(TPMT_TK_HASHCHECK, validation);
    END_CMD();
}

TPM_RC
TPM2_SequenceUpdate(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          sequenceHandle,     // IN
    TPM2B_MAX_BUFFER       *buffer              // IN
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_MAX_BUFFER, buffer);
    DISPATCH_CMD(SequenceUpdate, &sequenceHandle, 1, &session, 1);
    END_CMD();
}

TPM_RC
TPM2_Sign(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          keyHandle,          // IN
    TPM2B_DIGEST           *digest,             // IN
    TPMT_SIG_SCHEME        *inScheme,           // IN [opt]
    TPMT_TK_HASHCHECK      *validation,         // IN [opt]
    TPMT_SIGNATURE         *signature           // OUT
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_DIGEST, digest);
    TSS_MARSHAL(TPMT_SIG_SCHEME, inScheme ? inScheme : &NullSigScheme);
    TSS_MARSHAL(TPMT_TK_HASHCHECK, validation ? validation : &NullHashTk);
    DISPATCH_CMD(Sign, &keyHandle, 1, &session, 1);
    TSS_UNMARSHAL_FLAGGED(TPMT_SIGNATURE, signature);
    END_CMD();
}

TPM_RC
TSS_SequenceComplete(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          sequenceHandle,     // IN
    BYTE                   *data,               // IN
    UINT32                  dataSize,           // IN
    TPM2B_DIGEST           *result              // OUT
)
{
    TPM2B_MAX_BUFFER    dataBuf;// = { (UINT16)dataSize };
    dataBuf.t.size = (UINT16)dataSize;

    if (dataSize > MAX_DIGEST_BUFFER)
        return TPM_RC_SIZE;
    MemoryCopy(dataBuf.t.buffer, data, dataSize);

    return TPM2_SequenceComplete(tpm, session, sequenceHandle, &dataBuf, TPM_RH_NULL,
        result, NULL);
}

TPM_RC
TSS_SequenceUpdate(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          sequenceHandle,     // IN
    BYTE                   *data,               // IN
    UINT32                  dataSize            // IN
)
{
    TPM2B_MAX_BUFFER    dataBuf;// = { (UINT16)dataSize };
    dataBuf.t.size = (UINT16)dataSize;

    if (dataSize > MAX_DIGEST_BUFFER)
        return TPM_RC_SIZE;
    MemoryCopy(dataBuf.t.buffer, data, dataSize);

    return TPM2_SequenceUpdate(tpm, session, sequenceHandle, &dataBuf);
}

TPM_RC
TSS_Sign(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          keyHandle,          // IN
    TPM2B_DIGEST           *digest,             // IN
    TPMT_SIGNATURE         *signature           // OUT
)
{
    return TPM2_Sign(tpm, session, keyHandle, digest, NULL, NULL, signature);
}

// TSS extensions of the TPM 2.0 command interafce
TPM_RC
TSS_StartAuthSession(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM_SE                  sessionType,        // IN
    TPMI_ALG_HASH           authHash,           // IN
    TPMA_SESSION            sessAttrs,          // IN
    TSS_SESSION            *session             // OUT
)
{
    TPM_RC result;
    TPM2B_NONCE nonceCaller;
    UINT16 digestSize = TSS_GetDigestSize(authHash);
    nonceCaller.t.size = digestSize;
    TSS_RandomBytes(nonceCaller.t.buffer, digestSize);

    if (tpm == NULL || session == NULL)
    {
        LogError("Invalid parameter specified tpm: %p session: %p", tpm, session);
        result = TPM_RC_FAILURE;
    }
    else
    {
        result = TPM2_StartAuthSession(tpm, TPM_RH_NULL, TPM_RH_NULL, &nonceCaller, NULL,
            sessionType, NULL, authHash, &session->SessIn.sessionHandle, &session->SessOut.nonce);
        if (result == TPM_RC_SUCCESS)
        {
            TSS_COPY2B(session->SessIn.nonce, nonceCaller);
            session->SessIn.sessionAttributes = sessAttrs;
            session->SessOut.sessionAttributes = sessAttrs;
        }
        else
        {
            LogError("TPM2_StartAuthSession 0x%x: %s", result, TSS_StatusValueName(result));
        }
    }
    return result;
}

//
// TSS extensions of the TPM 2.0 command interafce
//

TPM_RC TSS_CreatePwAuthSession(TPM2B_AUTH* authValue, TSS_SESSION* session)
{
    TPM_RC result;
    if (authValue == NULL || session == NULL)
    {
        LogError("Invalid parameter specified authValue: %p, session: %p", authValue, session);
        result = TPM_RC_FAILURE;
    }
    else
    {
        session->SessIn.sessionHandle = TPM_RS_PW;
        session->SessIn.nonce.t.size = 0;
        session->SessIn.sessionAttributes.continueSession = SET;
        TSS_COPY2B(session->SessIn.hmac, *authValue);
        session->SessOut.sessionAttributes.continueSession = SET;
        result = TPM_RC_SUCCESS;
    }
    return result;
}

UINT32 TSS_GetTpmProperty(TSS_DEVICE* tpm, TPM_PT property)
{
    UINT32 result;
    TPMI_YES_NO                 more = NO;
    TPMS_CAPABILITY_DATA        capData;
    TPML_TAGGED_TPM_PROPERTY   *pProps = NULL;

    TPM_RC TSS_LastResponseCode = TPM2_GetCapability(tpm, TPM_CAP_TPM_PROPERTIES, property, 1, &more, &capData);
    if (TSS_LastResponseCode != TPM_RC_SUCCESS || capData.capability != TPM_CAP_TPM_PROPERTIES)
    {
        LogError("Get Capability failure");
        result = TSS_BAD_PROPERTY;
    }
    else if (capData.data.tpmProperties.count != 1)
    {
        LogError("Capability data count does not equal 1");
        result = TSS_BAD_PROPERTY;
    }
    else
    {
        pProps = &capData.data.tpmProperties;
        if (pProps->tpmProperty[0].property != property)
        {
            result = TSS_BAD_PROPERTY;
        }
        else
        {
            result = pProps->tpmProperty[0].value;
        }
    }
    return result;
}

TPM_RC TSS_CreatePrimary(TSS_DEVICE *tpm, TSS_SESSION *sess,
    TPM_HANDLE hierarchy, TPM2B_PUBLIC *inPub,
    TPM_HANDLE *outHandle, TPM2B_PUBLIC *outPub)
{
    TPM2B_SENSITIVE_CREATE  sensCreate = { 0 };
    TPM2B_DATA              outsideInfo = { {0} };
    TPML_PCR_SELECTION      creationPCR = { 0 };

    return TPM2_CreatePrimary(tpm, sess, hierarchy, &sensCreate,
        inPub, &outsideInfo, &creationPCR,
        outHandle, outPub, NULL, NULL, NULL);
}

TPM_RC TSS_Create(TSS_DEVICE *tpm, TSS_SESSION* sess, TPM_HANDLE parent, TPM2B_SENSITIVE_CREATE *sensCreate,
    TPM2B_PUBLIC *inPub, TPM2B_PRIVATE *outPriv, TPM2B_PUBLIC *outPub)
{
    TPM2B_SENSITIVE_CREATE  locSensCreate = { 0 };
    TPM2B_DATA              outsideInfo = { {0} };
    TPML_PCR_SELECTION      creationPCR = { 0 };

    return TPM2_Create(tpm, sess, parent,
        sensCreate ? sensCreate : &locSensCreate,
        inPub, &outsideInfo, &creationPCR,
        outPriv, outPub, NULL, NULL, NULL);
}

TPM_RC
TPM2_ActivateCredential(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *activateSess,       // IN/OUT
    TSS_SESSION            *keySess,            // IN/OUT
    TPMI_DH_OBJECT          activateHandle,     // IN
    TPMI_DH_OBJECT          keyHandle,          // IN
    TPM2B_ID_OBJECT        *credentialBlob,     // IN
    TPM2B_ENCRYPTED_SECRET *secret,             // IN
    TPM2B_DIGEST           *certInfo            // OUT
)
{
    TPM_HANDLE      handles[2];
    handles[0] = activateHandle;
    handles[1] = keyHandle;

    TSS_SESSION* sessions[2];// = { activateSess, keySess };
    sessions[0] = activateSess;
    sessions[1] = keySess;

    BEGIN_CMD();
    TSS_MARSHAL(TPM2B_ID_OBJECT, credentialBlob);
    TSS_MARSHAL(TPM2B_ENCRYPTED_SECRET, secret);
    DISPATCH_CMD(ActivateCredential, handles, 2, sessions, 2);
    TSS_UNMARSHAL(TPM2B_DIGEST, certInfo);
    END_CMD();
}

TPM_RC
TPM2_Create(
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
)
{
    BEGIN_CMD();
    TSS_MARSHAL(TPM2B_SENSITIVE_CREATE, inSensitive);
    TSS_MARSHAL(TPM2B_PUBLIC, inPublic);
    TSS_MARSHAL(TPM2B_DATA, outsideInfo);
    TSS_MARSHAL(TPML_PCR_SELECTION, creationPCR);
    DISPATCH_CMD(Create, &parentHandle, 1, &session, 1);
    TSS_UNMARSHAL(TPM2B_PRIVATE, outPrivate);
    TSS_UNMARSHAL_FLAGGED(TPM2B_PUBLIC, outPublic);
    TSS_UNMARSHAL_OPT(TPM2B_CREATION_DATA, creationData);
    TSS_UNMARSHAL_OPT(TPM2B_DIGEST, creationHash);
    TSS_UNMARSHAL_OPT(TPMT_TK_CREATION, creationTicket);
    END_CMD();
}

TPM_RC
TPM2_CreatePrimary(
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
)
{
    BEGIN_CMD();
    TSS_MARSHAL(TPM2B_SENSITIVE_CREATE, inSensitive);
    TSS_MARSHAL(TPM2B_PUBLIC, inPublic);
    TSS_MARSHAL(TPM2B_DATA, outsideInfo);
    TSS_MARSHAL(TPML_PCR_SELECTION, creationPCR);
    DISPATCH_CMD(CreatePrimary, &primaryHandle, 1, &session, 1);
    *objectHandle = cmdCtx->RetHandle;
    TSS_UNMARSHAL_FLAGGED(TPM2B_PUBLIC, outPublic);
    TSS_UNMARSHAL_OPT(TPM2B_CREATION_DATA, creationData);
    TSS_UNMARSHAL_OPT(TPM2B_DIGEST, creationHash);
    TSS_UNMARSHAL_OPT(TPMT_TK_CREATION, creationTicket);
    END_CMD();
}

TPM_RC
TPM2_EncryptDecrypt(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          keyHandle,          // IN
    TPMI_YES_NO             decrypt,            // IN
    TPM_ALG_ID              cipherMode,         // IN
    TPM2B_IV               *ivIn,               // IN [opt]
    TPM2B_MAX_BUFFER       *inData,             // IN
    TPM2B_MAX_BUFFER       *outData,            // OUT
    TPM2B_IV               *ivOut               // OUT [opt]
)
{
    BEGIN_CMD();
    TSS_MARSHAL(TPMI_YES_NO, &decrypt);
    TSS_MARSHAL(TPM_ALG_ID, &cipherMode);
    TSS_MARSHAL_OPT2B(TPM2B_IV, ivIn);
    TSS_MARSHAL(TPM2B_MAX_BUFFER, inData);
    DISPATCH_CMD(EncryptDecrypt, &keyHandle, 1, &session, 1);
    TSS_UNMARSHAL(TPM2B_MAX_BUFFER, outData);
    TSS_UNMARSHAL_OPT(TPM2B_IV, ivOut);
    END_CMD();
}

TPM_RC
TPM2_EvictControl(
    TSS_DEVICE           *tpm,                  // IN/OUT
    TSS_SESSION          *session,              // IN/OUT
    TPMI_RH_PROVISION     auth,                 // IN
    TPMI_DH_OBJECT        objectHandle,         // IN
    TPMI_DH_PERSISTENT    persistentHandle      // IN
)
{
    TPM_HANDLE handles[2];// = { auth , objectHandle};
    handles[0] = auth;
    handles[1] = objectHandle;

    BEGIN_CMD();
    TSS_MARSHAL(TPMI_DH_PERSISTENT, &persistentHandle);
    DISPATCH_CMD(EvictControl, handles, 2, &session, 1);
    END_CMD();
}

TPM_RC
TPM2_FlushContext(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPMI_DH_CONTEXT         flushHandle         // IN
)
{
    BEGIN_CMD();
    DISPATCH_CMD(FlushContext, &flushHandle, 1, NULL, 0);
    END_CMD();
}

TPM_RC
TPM2_GetCapability(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM_CAP                 capability,         // IN
    UINT32                  property,           // IN
    UINT32                  propertyCount,      // IN
    TPMI_YES_NO            *moreData,           // OUT
    TPMS_CAPABILITY_DATA   *capabilityData      // OUT
)
{
    BEGIN_CMD();
    TSS_MARSHAL(TPM_CAP, &capability);
    TSS_MARSHAL(UINT32, &property);
    TSS_MARSHAL(UINT32, &propertyCount);
    DISPATCH_CMD(GetCapability, NULL, 0, NULL, 0);
    TSS_UNMARSHAL(TPMI_YES_NO, moreData);
    TSS_UNMARSHAL(TPMS_CAPABILITY_DATA, capabilityData);
    END_CMD();
}

TPM_RC
TPM2_Hash(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM2B_MAX_BUFFER       *data,               // IN
    TPMI_ALG_HASH           hashAlg,            // IN
    TPMI_RH_HIERARCHY       hierarchy,          // IN [opt]
    TPM2B_DIGEST           *outHash,            // OUT
    TPMT_TK_HASHCHECK      *validation          // OUT [opt]
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_MAX_BUFFER, data);
    TSS_MARSHAL(TPMI_ALG_HASH, &hashAlg);
    TSS_MARSHAL(TPMI_RH_HIERARCHY, &hierarchy);
    DISPATCH_CMD(Hash, NULL, 0, NULL, 0);
    TSS_UNMARSHAL(TPM2B_DIGEST, outHash);
    TSS_UNMARSHAL_OPT(TPMT_TK_HASHCHECK, validation);
    END_CMD();
}

TPM_RC
TPM2_HashSequenceStart(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPM2B_AUTH             *auth,               // IN [opt]
    TPMI_ALG_HASH           hashAlg,            // IN
    TPMI_DH_OBJECT         *sequenceHandle      // OUT
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_AUTH, auth);
    TSS_MARSHAL(TPMI_ALG_HASH, &hashAlg);
    DISPATCH_CMD(HashSequenceStart, NULL, 0, NULL, 0);
    *sequenceHandle = cmdCtx->RetHandle;
    END_CMD();
}

TPM_RC
TPM2_HMAC_Start(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          handle,             // IN
    TPM2B_AUTH             *auth,               // IN [opt]
    TPMI_ALG_HASH           hashAlg,            // IN
    TPMI_DH_OBJECT         *sequenceHandle      // OUT
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_AUTH, auth);
    TSS_MARSHAL(TPMI_ALG_HASH, &hashAlg);
    DISPATCH_CMD(HMAC_Start, &handle, 1, &session, 1);
    *sequenceHandle = cmdCtx->RetHandle;
    END_CMD();
}

TPM_RC
TPM2_Import(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          parentHandle,       // IN
    TPM2B_DATA             *encryptionKey,      // IN
    TPM2B_PUBLIC           *objectPublic,       // IN
    TPM2B_PRIVATE          *duplicate,          // IN
    TPM2B_ENCRYPTED_SECRET *inSymSeed,          // IN
    TPMT_SYM_DEF_OBJECT    *symmetricAlg,       // IN
    TPM2B_PRIVATE          *outPrivate          // OUT
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_DATA, encryptionKey);
    TSS_MARSHAL(TPM2B_PUBLIC, objectPublic);
    TSS_MARSHAL(TPM2B_PRIVATE, duplicate);
    TSS_MARSHAL_OPT2B(TPM2B_ENCRYPTED_SECRET, inSymSeed);
    TSS_MARSHAL(TPMT_SYM_DEF_OBJECT, symmetricAlg ? symmetricAlg : &NullSymDefObject);
    DISPATCH_CMD(Import, &parentHandle, 1, &session, 1);
    TSS_UNMARSHAL(TPM2B_PRIVATE, outPrivate);
    END_CMD();
}

TPM_RC
TPM2_Load(
    TSS_DEVICE             *tpm,                // IN/OUT
    TSS_SESSION            *session,            // IN/OUT
    TPMI_DH_OBJECT          parentHandle,       // IN
    TPM2B_PRIVATE          *inPrivate,          // IN [opt]
    TPM2B_PUBLIC           *inPublic,           // IN
    TPM_HANDLE             *objectHandle,       // OUT
    TPM2B_NAME             *name                // OUT
)
{
    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_PRIVATE, inPrivate);
    TSS_MARSHAL(TPM2B_PUBLIC, inPublic);
    DISPATCH_CMD(Load, &parentHandle, 1, &session, 1);
    *objectHandle = cmdCtx->RetHandle;
    TSS_UNMARSHAL_OPT(TPM2B_NAME, name);
    END_CMD();
}

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
)
{
    TPM_HANDLE  handles[2];// = { authHandle, policySession };
    handles[0] = authHandle;
    handles[1] = policySession;

    BEGIN_CMD();
    TSS_MARSHAL_OPT2B(TPM2B_NONCE, nonceTPM);
    TSS_MARSHAL_OPT2B(TPM2B_DIGEST, cpHashA);
    TSS_MARSHAL_OPT2B(TPM2B_NONCE, policyRef);
    TSS_MARSHAL(INT32, &expiration);
    DISPATCH_CMD(PolicySecret, handles, 2, &session, 1);
    TSS_UNMARSHAL(TPM2B_TIMEOUT, timeout);
    TSS_UNMARSHAL_OPT(TPMT_TK_AUTH, policyTicket);
    END_CMD();
}

TPM_RC
TPM2_ReadPublic(
    TSS_DEVICE         *tpm,                    // IN/OUT
    TPMI_DH_OBJECT      objectHandle,           // IN
    TPM2B_PUBLIC       *outPublic,              // OUT
    TPM2B_NAME         *name,                   // OUT
    TPM2B_NAME         *qualifiedName           // OUT
)
{
    if (outPublic == NULL || name == NULL || qualifiedName == NULL)
    {
        LogError("Invalid parameter outPublic: %p, name: %p, qualifiedName: %p", outPublic, name, qualifiedName);
        return TPM_RC_FAILURE;
    }
    else
    {
        BEGIN_CMD();
        DISPATCH_CMD(ReadPublic, &objectHandle, 1, NULL, 0);
        TSS_UNMARSHAL_FLAGGED(TPM2B_PUBLIC, outPublic);
        TSS_UNMARSHAL(TPM2B_NAME, name);
        TSS_UNMARSHAL(TPM2B_NAME, qualifiedName);
        END_CMD();
    }
}

TPM_RC
TSS_DispatchCmd(
    TSS_DEVICE      *tpm,           // IN
    TPM_CC           cmdCode,       // IN: Command code
    TPM_HANDLE      *handles,       // IN (opt): Array of handles used by the command
    INT32            numHandles,    // IN: Number of handles in 'handles'
    TSS_SESSION    **sessions,      // IN (opt): Array of sessions
    INT32            numSessions,   // IN: Number of sessions in 'sessions'
    TSS_CMD_CONTEXT *cmdCtx         // IN/OUT: On input contains initialized parameter buffer
                                    //     On output contains complete command and response buffers
)
{
    TPM_RC result;
    TSS_STATUS  res;
    TPM_ST      tag;
    UINT32      expectedSize = 0;

    if (tpm == NULL || cmdCtx == NULL)
    {
        LogError("Invalid paramer specified tpm: %p, cmdCtx: %p", tpm, cmdCtx);
        result = TPM_RC_FAILURE;
    }
    else
    {
        cmdCtx->RespBufPtr = cmdCtx->RespBuffer;
        cmdCtx->RespParamSize = 0;
        cmdCtx->RetHandle = TPM_RH_UNASSIGNED;

        cmdCtx->CmdSize = TSS_BuildCommand(cmdCode, handles, numHandles, sessions, numSessions,
            cmdCtx->ParamBuffer, cmdCtx->ParamSize, cmdCtx->CmdBuffer, sizeof(cmdCtx->CmdBuffer));

        cmdCtx->RespSize = sizeof(cmdCtx->RespBuffer);
        res = TSS_SendCommand(tpm, cmdCtx->CmdBuffer, cmdCtx->CmdSize, cmdCtx->RespBuffer, (INT32*)&cmdCtx->RespSize);
        if (res != TSS_SUCCESS)
        {
            LogError("Sending command to tpm %d.", res);
            result = TPM_RC_COMMAND_CODE;
        }
        else
        {
            result = TPM_RC_SUCCESS;

            cmdCtx->RespBytesLeft = cmdCtx->RespSize;
            tpm->LastRawResponse = TPM_RC_NOT_USED;

            TSS_UNMARSHAL(TPMI_ST_COMMAND_TAG, &tag);
            TSS_UNMARSHAL(UINT32, &expectedSize);
            TSS_UNMARSHAL(TPM_RC, &tpm->LastRawResponse);

            if (cmdCtx->RespSize != expectedSize)
            {
                LogError("response size is not expected size.");
                result = TPM_RC_COMMAND_SIZE;//TSS_E_BAD_RESPONSE_LEN;
            }
            else
            {
                if (tpm->LastRawResponse == TPM_RC_SUCCESS)
                {
                    if (cmdCode == TPM_CC_CreatePrimary
                        || cmdCode == TPM_CC_Load
                        || cmdCode == TPM_CC_HMAC_Start
                        || cmdCode == TPM_CC_ContextLoad
                        || cmdCode == TPM_CC_LoadExternal
                        || cmdCode == TPM_CC_StartAuthSession
                        || cmdCode == TPM_CC_HashSequenceStart
                        || cmdCode == TPM_CC_CreateLoaded)
                    {
                        // Response buffer contains a handle returned by the TPM
                        TSS_UNMARSHAL(TPM_HANDLE, &cmdCtx->RetHandle);
                        //pAssert(cmdCtx->RetHandle != 0 && cmdCtx->RetHandle != TPM_RH_UNASSIGNED);
                        if (cmdCtx->RetHandle == 0 || cmdCtx->RetHandle == TPM_RH_UNASSIGNED)
                        {
                            LogError("unable to unmarshal return handle.");
                            result = TPM_RC_COMMAND_CODE;
                        }
                    }
                    if (result == TPM_RC_SUCCESS && tag == TPM_ST_SESSIONS)
                    {
                        // Response buffer contains a field specifying the size of returned parameters
                        TSS_UNMARSHAL(UINT32, &cmdCtx->RespParamSize);
                    }
                }

                if (result == TPM_RC_SUCCESS)
                {
                    // Remove error location information from the response code, if any
                    result = CleanResponseCode(tpm->LastRawResponse);
                }
            }
        }
    }
    return result;
}

TSS_STATUS
TSS_SendCommand(
    TSS_DEVICE  *tpm,               // IN: TPM device
    BYTE        *cmdBuffer,         // IN: Command buffer
    INT32        cmdSize,           // IN: Size of 'cmdBuffer' in bytes
    BYTE        *respBuffer,        // IN: Buffer for response to receive from TPM
    INT32       *respSize           // IN/OUT: IN: Capacity of 'respBuffer' in bytes
                                    //        OUT: Size of data in 'respBuffer'
)
{
    TSS_STATUS result;
    if (tpm == NULL || cmdBuffer == NULL)
    {
        LogError("Invalid tpm_comm_handle specified.");
        result = TSS_E_INVALID_PARAM;
    }
    else if (tpm->tpm_comm_handle == NULL)
    {
        LogError("Invalid tpm_comm_handle specified.");
        result = TSS_E_INVALID_PARAM;
    }
    else
    {
        // Send the command to the TPM
        if (tpm_comm_submit_command(tpm->tpm_comm_handle, cmdBuffer, cmdSize, respBuffer, (uint32_t*)respSize) != 0)
        {
            LogError("submitting command to TPM Communication.");
            result = TSS_E_TPM_TRANSACTION;
        }
        else
        {
            result = TSS_SUCCESS;
        }
    }
    return result;
}

//
// TSS helpers
//
TPMA_OBJECT ToTpmaObject(UINT32 attrs)
{
    TPMA_OBJECT tpma_object;
    memcpy(&tpma_object, &attrs, sizeof(TPMA_OBJECT));
    return tpma_object;
}

//
// TPM commands handling
//

// Returns the size of marhaled data  in 'commandBuffer' in bytes or 0 in case of
// failure (invalid parameters).
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
)
{
    UINT32  cmdSize = 0;
    BYTE   *pCmdSize = NULL;
    TPM_ST  tag = sessions ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;

    if ((cmdCode < 0x0000011f || cmdCode > 0x00000193)
        || (!handles && numHandles)
        || (!sessions && numSessions)
        || (!params && paramsSize)
        || (bufCapacity < 0)
        || (!cmdBuffer || (((UINT32)bufCapacity) < STD_RESPONSE_HEADER)))
    {
        return 0;
    }

    //
    // Marshal command header
    //

    cmdSize += TPMI_ST_COMMAND_TAG_Marshal(&tag, &cmdBuffer, &bufCapacity);

    // Do not know the final size of the command buffer yet.
    // Remeber the place to marshal it, and reserve space in the command buffer.
    pCmdSize = cmdBuffer;
    cmdSize += UINT32_Marshal((UINT32*)&cmdSize, &cmdBuffer, &bufCapacity);

    cmdSize += TPM_CC_Marshal(&cmdCode, &cmdBuffer, &bufCapacity);

    //
    // Marshal handles, if any
    //
    for (int i = 0; i < numHandles; i++)
    {
        cmdSize += TPM_HANDLE_Marshal(handles + i, &cmdBuffer, &bufCapacity);
    }
    // cmdSize = 14
    // bufCapacity - 4082

    //
    // Marshal sessions, if any
    //
    if (numSessions > 0)
    {
        // Do not know the size of the authorization area yet.
        // Remeber the place to marshal it, and marshal a placeholder value for now.
        BYTE   *pAuthSize = cmdBuffer; //t-sdks-
        UINT32  authSize = 0;

        // cmdSize - 14
        cmdSize += UINT32_Marshal((UINT32*)&authSize, &cmdBuffer, &bufCapacity);
        // cmdSize - 18

        // Marshal the sessions
        for (int i = 0; i < numSessions; i++)
        {
            authSize += TPMS_AUTH_COMMAND_Marshal(&sessions[i]->SessIn, &cmdBuffer, &bufCapacity);
        }
        // CmdBuffer - zure-devices.net/devices/jebrandoDevice/n1491340412

        // Update total marshaled size
        // 18 += 9;
        cmdSize += authSize;
        // 27

        // And marshal auth area size into the reserved space
        UINT32_Marshal((UINT32*)&authSize, &pAuthSize, NULL);
        // zure-devices.net/devices/jebrandoDevice
    }

    //
    // Marshal parameters, if any
    //
    if (params && paramsSize)
    {
        // 27
        cmdSize += BYTE_Array_Marshal(params, &cmdBuffer, &bufCapacity, paramsSize);
    }

    // Finally marshal total command size into the reserved space
    UINT32_Marshal((UINT32*)&cmdSize, &pCmdSize, NULL);

    return cmdSize;
} // TSS_BuildCommand()

// Misc TSS helpers
// Returns names of TPM_RC and TSS_STATUS codes
static const char* TSS_StatusValueName(UINT32 rc)
{
    static char unkCode[32];

    switch (rc)
    {
    case TPM_RC_SUCCESS:
        return "TPM_RC_SUCCESS";
    case TPM_RC_BAD_TAG:
        return "TPM_RC_BAD_TAG";
        //
        // VER1:
        //
    case TPM_RC_INITIALIZE:
        return "TPM_RC_INITIALIZE";
    case TPM_RC_FAILURE:
        return "TPM_RC_FAILURE";
    case TPM_RC_SEQUENCE:
        return "TPM_RC_SEQUENCE";
    case TPM_RC_PRIVATE:
        return "TPM_RC_PRIVATE";
    case TPM_RC_HMAC:
        return "TPM_RC_HMAC";
    case TPM_RC_DISABLED:
        return "TPM_RC_DISABLED";
    case TPM_RC_EXCLUSIVE:
        return "TPM_RC_EXCLUSIVE";
    case TPM_RC_AUTH_TYPE:
        return "TPM_RC_AUTH_TYPE";
    case TPM_RC_AUTH_MISSING:
        return "TPM_RC_AUTH_MISSING";
    case TPM_RC_POLICY:
        return "TPM_RC_POLICY";
    case TPM_RC_PCR:
        return "TPM_RC_PCR";
    case TPM_RC_PCR_CHANGED:
        return "TPM_RC_PCR_CHANGED";
    case TPM_RC_UPGRADE:
        return "TPM_RC_UPGRADE";
    case TPM_RC_TOO_MANY_CONTEXTS:
        return "TPM_RC_TOO_MANY_CONTEXTS";
    case TPM_RC_AUTH_UNAVAILABLE:
        return "TPM_RC_AUTH_UNAVAILABLE";
    case TPM_RC_REBOOT:
        return "TPM_RC_REBOOT";
    case TPM_RC_UNBALANCED:
        return "TPM_RC_UNBALANCED";
    case TPM_RC_COMMAND_SIZE:
        return "TPM_RC_COMMAND_SIZE";
    case TPM_RC_COMMAND_CODE:
        return "TPM_RC_COMMAND_CODE";
    case TPM_RC_AUTHSIZE:
        return "TPM_RC_AUTHSIZE";
    case TPM_RC_AUTH_CONTEXT:
        return "TPM_RC_AUTH_CONTEXT";
    case TPM_RC_NV_RANGE:
        return "TPM_RC_NV_RANGE";
    case TPM_RC_NV_SIZE:
        return "TPM_RC_NV_SIZE";
    case TPM_RC_NV_LOCKED:
        return "TPM_RC_NV_LOCKED";
    case TPM_RC_NV_AUTHORIZATION:
        return "TPM_RC_NV_AUTHORIZATION";
    case TPM_RC_NV_UNINITIALIZED:
        return "TPM_RC_NV_UNINITIALIZED";
    case TPM_RC_NV_SPACE:
        return "TPM_RC_NV_SPACE";
    case TPM_RC_NV_DEFINED:
        return "TPM_RC_NV_DEFINED";
    case TPM_RC_BAD_CONTEXT:
        return "TPM_RC_BAD_CONTEXT";
    case TPM_RC_CPHASH:
        return "TPM_RC_CPHASH";
    case TPM_RC_PARENT:
        return "TPM_RC_PARENT";
    case TPM_RC_NEEDS_TEST:
        return "TPM_RC_NEEDS_TEST";
    case TPM_RC_NO_RESULT:
        return "TPM_RC_NO_RESULT";
    case TPM_RC_SENSITIVE:
        return "TPM_RC_SENSITIVE";
    case RC_MAX_FM0:
        return "RC_MAX_FM0";
        //
        // FMT1
        //
    case TPM_RC_ASYMMETRIC:
        return "TPM_RC_ASYMMETRIC";
    case TPM_RC_ATTRIBUTES:
        return "TPM_RC_ATTRIBUTES";
    case TPM_RC_HASH:
        return "TPM_RC_HASH";
    case TPM_RC_VALUE:
        return "TPM_RC_VALUE";
    case TPM_RC_HIERARCHY:
        return "TPM_RC_HIERARCHY";
    case TPM_RC_KEY_SIZE:
        return "TPM_RC_KEY_SIZE";
    case TPM_RC_MGF:
        return "TPM_RC_MGF";
    case TPM_RC_MODE:
        return "TPM_RC_MODE";
    case TPM_RC_TYPE:
        return "TPM_RC_TYPE";
    case TPM_RC_HANDLE:
        return "TPM_RC_HANDLE";
    case TPM_RC_KDF:
        return "TPM_RC_KDF";
    case TPM_RC_RANGE:
        return "TPM_RC_RANGE";
    case TPM_RC_AUTH_FAIL:
        return "TPM_RC_AUTH_FAIL";
    case TPM_RC_NONCE:
        return "TPM_RC_NONCE";
    case TPM_RC_PP:
        return "TPM_RC_PP";
    case TPM_RC_SCHEME:
        return "TPM_RC_SCHEME";
    case TPM_RC_SIZE:
        return "TPM_RC_SIZE";
    case TPM_RC_SYMMETRIC:
        return "TPM_RC_SYMMETRIC";
    case TPM_RC_TAG:
        return "TPM_RC_TAG";
    case TPM_RC_SELECTOR:
        return "TPM_RC_SELECTOR";
    case TPM_RC_INSUFFICIENT:
        return "TPM_RC_INSUFFICIENT";
    case TPM_RC_SIGNATURE:
        return "TPM_RC_SIGNATURE";
    case TPM_RC_KEY:
        return "TPM_RC_KEY";
    case TPM_RC_POLICY_FAIL:
        return "TPM_RC_POLICY_FAIL";
    case TPM_RC_INTEGRITY:
        return "TPM_RC_INTEGRITY";
    case TPM_RC_TICKET:
        return "TPM_RC_TICKET";
    case TPM_RC_RESERVED_BITS:
        return "TPM_RC_RESERVED_BITS";
    case TPM_RC_BAD_AUTH:
        return "TPM_RC_BAD_AUTH";
    case TPM_RC_EXPIRED:
        return "TPM_RC_EXPIRED";
    case TPM_RC_POLICY_CC:
        return "TPM_RC_POLICY_CC";
    case TPM_RC_BINDING:
        return "TPM_RC_BINDING";
    case TPM_RC_CURVE:
        return "TPM_RC_CURVE";
    case TPM_RC_ECC_POINT:
        return "TPM_RC_ECC_POINT";
        //
        // WARN
        //
    case TPM_RC_CONTEXT_GAP:
        return "TPM_RC_CONTEXT_GAP";
    case TPM_RC_OBJECT_MEMORY:
        return "TPM_RC_OBJECT_MEMORY";
    case TPM_RC_SESSION_MEMORY:
        return "TPM_RC_SESSION_MEMORY";
    case TPM_RC_MEMORY:
        return "TPM_RC_MEMORY";
    case TPM_RC_SESSION_HANDLES:
        return "TPM_RC_SESSION_HANDLES";
    case TPM_RC_OBJECT_HANDLES:
        return "TPM_RC_OBJECT_HANDLES";
    case TPM_RC_LOCALITY:
        return "TPM_RC_LOCALITY";
    case TPM_RC_YIELDED:
        return "TPM_RC_YIELDED";
    case TPM_RC_CANCELED:
        return "TPM_RC_CANCELED";
    case TPM_RC_TESTING:
        return "TPM_RC_TESTING";
    case TPM_RC_REFERENCE_H0:
        return "TPM_RC_REFERENCE_H0";
    case TPM_RC_REFERENCE_H1:
        return "TPM_RC_REFERENCE_H1";
    case TPM_RC_REFERENCE_H2:
        return "TPM_RC_REFERENCE_H2";
    case TPM_RC_REFERENCE_H3:
        return "TPM_RC_REFERENCE_H3";
    case TPM_RC_REFERENCE_H4:
        return "TPM_RC_REFERENCE_H4";
    case TPM_RC_REFERENCE_H5:
        return "TPM_RC_REFERENCE_H5";
    case TPM_RC_REFERENCE_H6:
        return "TPM_RC_REFERENCE_H6";
    case TPM_RC_REFERENCE_S0:
        return "TPM_RC_REFERENCE_S0";
    case TPM_RC_REFERENCE_S1:
        return "TPM_RC_REFERENCE_S1";
    case TPM_RC_REFERENCE_S2:
        return "TPM_RC_REFERENCE_S2";
    case TPM_RC_REFERENCE_S3:
        return "TPM_RC_REFERENCE_S3";
    case TPM_RC_REFERENCE_S4:
        return "TPM_RC_REFERENCE_S4";
    case TPM_RC_REFERENCE_S5:
        return "TPM_RC_REFERENCE_S5";
    case TPM_RC_REFERENCE_S6:
        return "TPM_RC_REFERENCE_S6";
    case TPM_RC_NV_RATE:
        return "TPM_RC_NV_RATE";
    case TPM_RC_LOCKOUT:
        return "TPM_RC_LOCKOUT";
    case TPM_RC_RETRY:
        return "TPM_RC_RETRY";
    case TPM_RC_NV_UNAVAILABLE:
        return "TPM_RC_NV_UNAVAILABLE";
    case TPM_RC_NOT_USED:
        return "TPM_RC_NOT_USED";

        //
        // TSS general
        //
    case TSS_E_INVALID_PARAM:
        return "TSS_E_INVALID_PARAM";
    case TSS_E_SOCK_INIT:
        return "TSS_E_SOCK_INIT";
    case TSS_E_SOCK_SHUTDOWN:
        return "TSS_E_SOCK_SHUTDOWN";
    case TSS_E_TPM_CONNECT:
        return "TSS_E_TPM_CONNECT";
    case TSS_E_TPM_SIM_INCOMPAT_VER:
        return "TSS_E_TPM_SIM_INCOMPAT_VER";
    case TSS_E_TPM_SIM_STARTUP:
        return "TSS_E_TPM_SIM_STARTUP";

        //
        // TSS communication with TPM
        //
    case TSS_E_COMM:
        return "TSS_E_COMM";
    case TSS_E_TPM_TRANSACTION:
        return "TSS_E_TPM_TRANSACTION";
    case TSS_E_TPM_SIM_BAD_ACK:
        return "TSS_E_TPM_SIM_BAD_ACK";
    case TSS_E_BAD_RESPONSE:
        return "TSS_E_BAD_RESPONSE";
    case TSS_E_BAD_RESPONSE_LEN:
        return "TSS_E_BAD_RESPONSE_LEN";
    }

    snprintf(unkCode, sizeof(unkCode), "0x%08X", rc);
    return unkCode;
} // TSS_StatusValueName()

//// Returns mesages corresponding to TSS_STATUS codes
//static const char* TSS_GetStatusMessage(TSS_STATUS status)
//{
//    switch (status)
//    {
//    case TSS_SUCCESS:
//        return "TSS operation completed successfully";
//    case TSS_E_INVALID_PARAM:
//        return "Invalid parameter";
//    case TSS_E_SOCK_INIT:
//        return "Failed to initialize Socket subsystem";
//    case TSS_E_SOCK_SHUTDOWN:
//        return "Failed to shut down Socket subsystem";
//    case TSS_E_TPM_CONNECT:
//        return "Failed to establish TPM connection";
//    case TSS_E_TPM_SIM_INCOMPAT_VER:
//        return "Incompatible TPM Simulator version";
//    case TSS_E_TPM_SIM_STARTUP:
//        return "Unexpected TPM2_Startup() failure";
//
//        // TSS communication with TPM
//
//    case TSS_E_COMM:
//        return "General TPM communication channel failure";
//    case TSS_E_TPM_TRANSACTION:
//        return "TPM transaction failed";
//    case TSS_E_TPM_SIM_BAD_ACK:
//        return "Bad ACK tag in TPM Simulator transaction";
//    case TSS_E_BAD_RESPONSE:
//        return "Invalid TPM response buffer";
//    case TSS_E_BAD_RESPONSE_LEN:
//        return "Bad length field in TPM response buffer";
//    default:
//        return TSS_StatusValueName(status);
//    }
//} // TSS_GetStatusMessage()

UINT16 TSS_GetDigestSize(TPM_ALG_ID hashAlg)
{
    switch (hashAlg)
    {
        case TPM_ALG_SHA1:   return 0x14;
        case TPM_ALG_SHA256: return 0x20;
        case TPM_ALG_SHA384: return 0x30;
    }
    return 0;
}

TPM_RC
TPM2_StartAuthSession(
    TSS_DEVICE             *tpm,                // IN/OUT
    TPMI_DH_OBJECT          tpmKey,             // IN
    TPMI_DH_ENTITY          bind,               // IN
    TPM2B_NONCE            *nonceCaller,        // IN
    TPM2B_ENCRYPTED_SECRET *encryptedSalt,      // IN
    TPM_SE                  sessionType,        // IN
    TPMT_SYM_DEF           *symmetric,          // IN
    TPMI_ALG_HASH           authHash,           // IN
    TPMI_SH_AUTH_SESSION   *sessionHandle,      // OUT
    TPM2B_NONCE            *nonceTPM            // OUT
)
{
    TPM_HANDLE handles[2];
    handles[0] = tpmKey;
    handles[1] = bind;

    BEGIN_CMD();
    TSS_MARSHAL(TPM2B_NONCE, nonceCaller);
    TSS_MARSHAL_OPT2B(TPM2B_ENCRYPTED_SECRET, encryptedSalt);
    TSS_MARSHAL(TPM_SE, &sessionType);
    TSS_MARSHAL(TPMT_SYM_DEF, symmetric ? symmetric : &NullSymDef);
    TSS_MARSHAL(TPMI_ALG_HASH, &authHash);
    DISPATCH_CMD(StartAuthSession, handles, 2, NULL, 0);
    *sessionHandle = cmdCtx->RetHandle;
    TSS_UNMARSHAL(TPM2B_NONCE, nonceTPM);
    END_CMD();
}

TPM_RC
TPM2_Startup(
    TSS_DEVICE     *tpm,                // IN/OUT
    TPM_SU          startupType         // IN
)
{
    BEGIN_CMD();
    TSS_MARSHAL(TPM_SU, &startupType);
    DISPATCH_CMD(Startup, NULL, 0, NULL, 0);
    END_CMD();
}

void TSS_RandomBytes(
    BYTE    *buf,           // OUT: buffer to fill with random bytes
    int      bufSize        // Number of random bytes to generate
)
{
    for (; bufSize > 0; --bufSize)
        *buf++ = (BYTE)rand();
}
