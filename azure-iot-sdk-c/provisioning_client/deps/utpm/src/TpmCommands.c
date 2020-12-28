
#include "Tss.h"
#include "tpm/Marshal_fp.h"
#include "tpm/Memory_fp.h"


#define MAX_COMMAND_BUFFER      4096
#define MAX_RESPONSE_BUFFER     MAX_COMMAND_BUFFER

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


static TSS_CMD_CONTEXT  CmdCtx;

#define BEGIN_CMD()  \
    TPM_RC           cmdResult = TPM_RC_SUCCESS;                            \
    TSS_CMD_CONTEXT *cmdCtx = &CmdCtx;                                      \
    INT32            sizeParamBuf = sizeof(cmdCtx->ParamBuffer);            \
    BYTE            *paramBuf = cmdCtx->ParamBuffer;                        \
    cmdCtx->ParamSize = 0

#define END_CMD()  \
    return cmdResult

#define DISPATCH_CMD(cmdName, pHandles, numHandles, pSessions, numSessions) \
    cmdResult = TSS_DispatchCmd(tpm, TPM_CC_##cmdName,                          \
                                pHandles, numHandles, pSessions, numSessions,   \
                                cmdCtx);                                        \
    if (cmdResult != TPM_RC_SUCCESS)                                            \
        return cmdResult


#define TSS_MARSHAL(Type, pValue) \
    cmdCtx->ParamSize += Type##_Marshal(pValue, &paramBuf, &sizeParamBuf)


#define TSS_UNMARSHAL(Type, pValue) \
{                                                                                   \
    if (   Type##_Unmarshal(pValue, &cmdCtx->RespBufPtr, &cmdCtx->RespBytesLeft)    \
        != TPM_RC_SUCCESS)                                                          \
        return TSS_E_BAD_RESPONSE;                                                 \
}

#define TSS_UNMARSHAL_FLAGGED(Type, pValue) \
{                                                                                       \
    if (   Type##_Unmarshal(pValue, &cmdCtx->RespBufPtr, &cmdCtx->RespBytesLeft, TRUE)  \
        != TPM_RC_SUCCESS)                                                              \
        return TSS_E_BAD_RESPONSE;                                                     \
}

#define TSS_COPY2B(dst2b, src2b) \
    MemoryCopy2B(&(dst2b).b, &(src2b).b, sizeof((dst2b).t.buffer))


static bool IsCommMediumError(UINT32 code)
{
    // TBS or TPMSim protocol error
    return (code & 0xFFFF0000) == 0x80280000;
}

static TPM_RC CleanResponseCode(TPM_RC rawResponse)
{
    if (IsCommMediumError(rawResponse))
        return rawResponse;

    UINT32 mask = rawResponse & RC_FMT1 ? RC_FMT1 | 0x3F
        : TPM_RC_NOT_USED; // RC_WARN | RC_VER1 | 0x7F
    return rawResponse & mask;
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
    TSS_STATUS  res;
    TPM_ST      tag;
    UINT32      expectedSize = 0;

    cmdCtx->RespBufPtr = cmdCtx->RespBuffer;
    cmdCtx->RespParamSize = 0;
    cmdCtx->RetHandle = TPM_RH_UNASSIGNED;

    cmdCtx->CmdSize = TSS_BuildCommand(cmdCode,
        handles, numHandles,
        sessions, numSessions,
        cmdCtx->ParamBuffer, cmdCtx->ParamSize,
        cmdCtx->CmdBuffer, sizeof(cmdCtx->CmdBuffer));

    cmdCtx->RespSize = sizeof(cmdCtx->RespBuffer);
    res = TSS_SendCommand(tpm, cmdCtx->CmdBuffer, cmdCtx->CmdSize,
        cmdCtx->RespBuffer, &cmdCtx->RespSize);
    if (res != TSS_SUCCESS)
        return res;

    //
    // Unmarshal command header
    //

    if (*(TPM_ST*)cmdCtx->RespBuffer == TPM_ST_NO_SESSIONS
        && *(TPM_ST*)cmdCtx->RespBuffer == TPM_ST_SESSIONS)
    {
        return TPM_RC_BAD_TAG;
    }

    cmdCtx->RespBytesLeft = cmdCtx->RespSize;
    tpm->LastRawResponse = TPM_RC_NOT_USED;

    TSS_UNMARSHAL(TPMI_ST_COMMAND_TAG, &tag);
    TSS_UNMARSHAL(UINT32, &expectedSize);
    TSS_UNMARSHAL(TPM_RC, &tpm->LastRawResponse);

    if (cmdCtx->RespSize != expectedSize)
        return TSS_E_BAD_RESPONSE_LEN;

    if (cmdCode == TPM_CC_CreatePrimary ||
        cmdCode == TPM_CC_Load ||
        cmdCode == TPM_CC_HMAC_Start ||
        cmdCode == TPM_CC_ContextLoad ||
        cmdCode == TPM_CC_LoadExternal ||
        cmdCode == TPM_CC_StartAuthSession ||
        cmdCode == TPM_CC_HashSequenceStart ||
        cmdCode == TPM_CC_CreateLoaded)
    {
        // Response buffer contains a handle returned by the TPM
        TSS_UNMARSHAL(TPM_HANDLE, &cmdCtx->RetHandle);
        pAssert(cmdCtx->RetHandle != 0 && cmdCtx->RetHandle != TPM_RH_UNASSIGNED);
    }

    if (tag == TPM_ST_SESSIONS)
    {
        // Response buffer contains a field specifying the size of returned parameters
        TSS_UNMARSHAL(UINT32, &cmdCtx->RespParamSize);
    }

    // Remove error location information from the response code, if any
    return CleanResponseCode(tpm->LastRawResponse);
}

//
// TSS extensions of the TPM 2.0 command interafce
//

TPM2B_AUTH      NullAuth = { 0 };
TSS_SESSION     NullPwSession;

TPM_RC
TSS_CreatePwAuthSession(
    TPM2B_AUTH      *authValue,     // IN
    TSS_SESSION     *session        // OUT
    )
{
    session->SessIn.sessionHandle = TPM_RS_PW;
    session->SessIn.nonce.t.size = 0;
    session->SessIn.sessionAttributes.continueSession = SET;
    TSS_COPY2B(session->SessIn.hmac, *authValue);
    session->SessOut.sessionAttributes.continueSession = SET;
    return TPM_RC_SUCCESS;
}

TPM_RC
TSS_StartHmacAuthSession(
    TSS_DEVICE         *tpm,            // IN/OUT
    TPM_SE              sessionType,    // IN
    TPMI_ALG_HASH       authHash,       // IN
    TPMA_SESSION        sessAttrs,      // IN
    TSS_SESSION        *session         // OUT
    )
{
    UINT16          digestSize = TSS_GetDigestSize(authHash);
    TPM2B_NONCE     nonceCaller = { digestSize };
    TSS_RandomBytes(nonceCaller.t.buffer, digestSize);

    TPM_RC rc = TPM2_StartAuthSession(tpm, TPM_RH_NULL, TPM_RH_NULL, &nonceCaller, NULL,
        TPM_SE_HMAC, NULL, authHash,
        &session->SessIn.sessionHandle,
        &session->SessOut.nonce);
    if (rc == TPM_RC_SUCCESS)
    {
        TSS_COPY2B(session->SessIn.nonce, nonceCaller);
        session->SessIn.sessionAttributes = sessAttrs;
        session->SessOut.sessionAttributes = sessAttrs;
    }
    return rc;
}

//
// TPM 2.0 command interafce
//


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
    TSS_UNMARSHAL(TPM2B_CREATION_DATA, creationData);
    TSS_UNMARSHAL(TPM2B_DIGEST, creationHash);
    TSS_UNMARSHAL(TPMT_TK_CREATION, creationTicket);
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
    TSS_UNMARSHAL(TPM2B_CREATION_DATA, creationData);
    TSS_UNMARSHAL(TPM2B_DIGEST, creationHash);
    TSS_UNMARSHAL(TPMT_TK_CREATION, creationTicket);
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
    TPM_HANDLE  handles[2] = { auth , objectHandle};
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
TPM2_ReadPublic(
    TSS_DEVICE         *tpm,                    // IN/OUT
    TPMI_DH_OBJECT      objectHandle,           // IN
    TPM2B_PUBLIC       *outPublic,              // OUT
    TPM2B_NAME         *name,                   // OUT
    TPM2B_NAME         *qualifiedName           // OUT
    )
{
    BEGIN_CMD();
    DISPATCH_CMD(ReadPublic, &objectHandle, 1, NULL, 0);
    TSS_UNMARSHAL_FLAGGED(TPM2B_PUBLIC, outPublic);
    TSS_UNMARSHAL(TPM2B_NAME, name);
    TSS_UNMARSHAL(TPM2B_NAME, qualifiedName);
    END_CMD();
}

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
    )
{
    TPM_HANDLE  handles[] = { tpmKey, bind };
    BEGIN_CMD();
    TSS_MARSHAL(TPM2B_NONCE, nonceCaller);
    TSS_MARSHAL(TPM2B_ENCRYPTED_SECRET, encryptedSalt);
    TSS_MARSHAL(TPM_SE, sessionType);
    TSS_MARSHAL(TPMT_SYM_DEF, symmetric);
    TSS_MARSHAL(TPMI_ALG_HASH, authHash);
    DISPATCH_CMD(StartAuthSession, handles, 2, NULL, 0);
    TSS_UNMARSHAL_FLAGGED(TPMI_SH_AUTH_SESSION, sessionHandle);
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

