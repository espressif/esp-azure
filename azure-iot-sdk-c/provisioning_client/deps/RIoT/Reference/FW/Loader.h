/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#ifdef __cplusplus
extern "C" {
#endif

#include "RIoT.h"
#include "RIoTSim.h"

#ifdef LOADER_EXPORTS
#define FW_API __declspec(dllexport)
#else
#define FW_API __declspec(dllimport)
#endif

FW_API void FirmwareEntry(
    ecc_publickey    *DeviceIDPub,
    ecc_publickey    *AliasKeyPub,
    ecc_privatekey   *AliasKeyPriv,
    char             *AliasKeyCert
);

#ifdef __cplusplus
}
#endif
