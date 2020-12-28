#ifndef _RIOT_X509_BLDR_H
#define _RIOT_X509_BLDR_H

#include "RiotCrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RIOT_X509_SNUM_LEN  0x05

// KeyUsage :: = BIT STRING{
//     digitalSignature(0),
//     nonRepudiation(1),
//     keyEncipherment(2),
//     dataEncipherment(3),
//     keyAgreement(4),
//     keyCertSign(5),
//     cRLSign(6)
// }
#define RIOT_X509_KEY_USAGE 0x4  // keyCertSign

// Const x509 "to be signed" data
typedef struct
{
    uint8_t SerialNum[RIOT_X509_SNUM_LEN];
    const char *IssuerCommon;
    const char *IssuerOrg;
    const char *IssuerCountry;
    const char *ValidFrom;
    const char *ValidTo;
    const char *SubjectCommon;
    const char *SubjectOrg;
    const char *SubjectCountry;
} RIOT_X509_TBS_DATA;

int
X509GetDeviceCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *DevIdKeyPub
);

int
X509MakeDeviceCert(
    DERBuilderContext   *DeviceIDCert,
    RIOT_ECC_SIGNATURE  *TbsSig
);

int
X509GetAliasCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *AliasKeyPub,
    RIOT_ECC_PUBLIC     *DevIdKeyPub,
    uint8_t             *Fwid,
    uint32_t             FwidLen
);

int
X509MakeAliasCert(
    DERBuilderContext   *AliasCert,
    RIOT_ECC_SIGNATURE  *TbsSig
);

int
X509GetDEREccPub(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub
);

int
X509GetDEREcc(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub,
    RIOT_ECC_PRIVATE     Priv
);

int
X509GetDERCsrTbs(
    DERBuilderContext   *Context,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *DeviceIDPub
);

int
X509GetDERCsr(
    DERBuilderContext   *Context,
    RIOT_ECC_SIGNATURE  *Signature
);

int
X509GetRootCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *RootKeyPub
);

int
X509MakeRootCert(
    DERBuilderContext   *AliasCert,
    RIOT_ECC_SIGNATURE  *TbsSig
);

#ifdef __cplusplus
}
#endif
#endif