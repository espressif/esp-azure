
//
// Interface with TPM devices
//

#include "Tss.h"


//
// Interface with the TPM Simulator
//

TSS_STATUS TSS_Init()
{
    TSS_CreatePwAuthSession(&NullAuth, &NullPwSession);

    if (!SockInit())
        return TSS_E_SOCK_INIT;
    return TSS_SUCCESS;
}

TSS_STATUS TSS_Shutdown()
{
    if (!SockShutdown())
        return TSS_E_SOCK_SHUTDOWN;
    return TSS_SUCCESS;
}


enum TpmSimCommands {
    Remote_SignalPowerOn = 1,
    //SignalPowerOff = 2,
    Remote_SendCommand = 8,
    Remote_SignalNvOn = 11,
    //SignalNvOff = 12,
    Remote_Handshake = 15,
    Remote_SessionEnd = 20,
    Remote_Stop = 21,
};


// An ACK in the TPM Sim protocol is a zero UINT32
bool GetAck(SOCKET s)
{
    uint32_t endTag = 1;
    return SockReadUint(s, &endTag) ? endTag == 0 : false;
}

TSS_STATUS
TSS_ConnectToLocalTpmSim(
    TSS_DEVICE* tpm          // OUT
    )
{
    TSS_STATUS  res = TSS_SUCCESS;
    int         tpmClientVer = 1;
    int         tpmSimVer = 0;
    bool        ok = true;
    SOCKET      s;

    if (!tpm || tpm->TpmInfo)
        return TSS_E_INVALID_PARAM;

    s = SockConnect("127.0.0.1", 2321);
    if (s == INVALID_SOCKET)
        return TSS_E_TPM_CONNECT;

    //
    // Shake hands with the TPM Simulator
    //

    // Send hand shake request
    ok = ok && SockWriteUint(s, Remote_Handshake);

    // Send desired protocol version
    ok = ok && SockWriteUint(s, tpmClientVer);

    // Read protocol version supported by the server
    ok = ok && SockReadUint(s, &tpmSimVer);

    if (ok && tpmClientVer != tpmSimVer)
    {
        ok = false;
        res = TSS_E_TPM_SIM_INCOMPAT_VER;
    }

    // Read characteristics of the TPM end its environment
    ok = ok && SockReadUint(s, &tpm->TpmInfo);

    // Get confirmation that the hand-shake completed successfully
    ok = ok && GetAck(s);

    if (ok)
    {
        tpm->TpmConnHandle.Socket = s;
        tpm->TpmInfo |= TSS_SocketConn;
    }
    else
    {
        SockClose(s);
        return res != TSS_SUCCESS ? res : TSS_E_TPM_TRANSACTION;
    }

    //
    // Power on the simulator
    //

    // Use platform interface of the simulator
    s = SockConnect("127.0.0.1", 2322);
    if (s == INVALID_SOCKET)
        ok = false;

    ok = ok && SockWriteUint(s, Remote_SignalPowerOn);
    ok = ok && GetAck(s);
    ok = ok && SockWriteUint(s, Remote_SignalNvOn);
    ok = ok && GetAck(s);
    SockClose(s);

    if (ok)
    {
        TPM_RC rc = TPM2_Startup(tpm, TPM_SU_CLEAR);
        if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE)
        {
            ok = false;
            res = rc; // TSS_E_TPM_SIM_STARTUP;
        }
    }

    if (!ok)
    {
        SockClose(tpm->TpmConnHandle.Socket);
        tpm->TpmInfo = 0;
        return res != TSS_SUCCESS ? res : TSS_E_TPM_TRANSACTION;;
    }

    return res;
} // TSS_ConnectToLocalTpmSim()

TSS_STATUS
TSS_DisconnectFromTpm(
    TSS_DEVICE* tpm          // IN
    )
{
    SOCKET s;

    if (!tpm || !(tpm->TpmInfo & TSS_SocketConn))
        return TSS_E_INVALID_PARAM;

    s = tpm->TpmConnHandle.Socket;
    if (s != INVALID_SOCKET)
    {
        SockWriteUint(s, Remote_SessionEnd);
        SockClose(s);
    }
    tpm->TpmInfo = 0;

    return TSS_SUCCESS;
} // TSS_DisconnectFromTpm()

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
    bool    ok = true;
    BYTE    locality = 0;
    SOCKET  s;

    if (!tpm)
        return TSS_E_INVALID_PARAM;

    if (!(tpm->TpmInfo & TSS_SocketConn))
        return TSS_E_NOT_IMPL;

    s = tpm->TpmConnHandle.Socket;

    // Send the command to the TPM
    ok = ok && SockWriteUint(s, Remote_SendCommand);
    ok = ok && SockWriteBytes(s, &locality, 1);
    ok = ok && SockWriteVarBytes(s, cmdBuffer, cmdSize);

    // Read the TPM response
    ok = ok && SockReadVarBytes(s, respBuffer, respSize, *respSize);
    ok = ok && GetAck(s);

    return ok ? TSS_SUCCESS : TSS_E_TPM_TRANSACTION;
}

