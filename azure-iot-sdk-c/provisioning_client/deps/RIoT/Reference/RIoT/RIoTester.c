/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

#include <stdio.h>
#include <string.h>
#include <RiotCrypt.h>

const char *str0 = "abc";
const char *str1 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

// HASH/HMAC
// SHA1 is "internal only" but we verify it here anyway
const uint8_t str0_sha1[SHA1_DIGEST_LENGTH] =   {0xa9, 0x99, 0x3e, 0x36, 
                                                 0x47, 0x06, 0x81, 0x6a,
                                                 0xba, 0x3e, 0x25, 0x71, 
                                                 0x78, 0x50, 0xc2, 0x6c, 
                                                 0x9c, 0xd0, 0xd8, 0x9d};
const uint8_t str0_sha256[RIOT_DIGEST_LENGTH] = {0xba, 0x78, 0x16, 0xbf, 
                                                 0x8f, 0x01, 0xcf, 0xea,
                                                 0x41, 0x41, 0x40, 0xde,
                                                 0x5d, 0xae, 0x22, 0x23,
                                                 0xb0, 0x03, 0x61, 0xa3,
                                                 0x96, 0x17, 0x7a, 0x9c,
                                                 0xb4, 0x10, 0xff, 0x61,
                                                 0xf2, 0x00, 0x15, 0xad};
const uint8_t str1_sha1[SHA1_DIGEST_LENGTH] =   {0x84, 0x98, 0x3E, 0x44,
                                                 0x1C, 0x3B, 0xD2, 0x6E,
                                                 0xBA, 0xAE, 0x4A, 0xA1,
                                                 0xF9, 0x51, 0x29, 0xE5,
                                                 0xE5, 0x46, 0x70, 0xF1};
const uint8_t str1_sha256[RIOT_DIGEST_LENGTH] = {0x24, 0x8D, 0x6A, 0x61,
                                                 0xD2, 0x06, 0x38, 0xB8,
                                                 0xE5, 0xC0, 0x26, 0x93,
                                                 0x0C, 0x3E, 0x60, 0x39,
                                                 0xA3, 0x3C, 0xE4, 0x59,
                                                 0x64, 0xFF, 0x21, 0x67,
                                                 0xF6, 0xEC, 0xED, 0xD4,
                                                 0x19, 0xDB, 0x06, 0xC1};
const uint8_t strc_sha256[RIOT_DIGEST_LENGTH] = {0xAE, 0x1D, 0xC6, 0xDF,
                                                 0xAA, 0x79, 0x81, 0x2E,
                                                 0xB3, 0xF4, 0xD2, 0xB7,
                                                 0xAE, 0xA0, 0x2E, 0xD0,
                                                 0xDE, 0xB3, 0xE8, 0x86,
                                                 0x64, 0x7B, 0xB2, 0xF3,
                                                 0x48, 0x28, 0x19, 0xCA,
                                                 0x53, 0xC8, 0xCB, 0x9D};

// HKDF
const uint8_t hkIKM[22]  = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
const uint8_t hkCtx[13]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
const uint8_t hkInf[10]  = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
const uint8_t hkBTS[42]  = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
                            0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
                            0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
                            0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

#if RIOT_COORDMAX == 0x20
// ecc
const uint8_t pubX[RIOT_COORDMAX]   = {0x68, 0xF1, 0x0D, 0x9A, 0xEF, 0x2C, 0x02, 0xF9, 0x3D, 
                                       0x6F, 0x82, 0xB4, 0x34, 0x07, 0x1C, 0x17, 0xD5, 0x2C,
                                       0x75, 0xE4, 0x3C, 0x4D, 0x18, 0x10, 0x10, 0xDC, 0x4B,
                                       0x2B, 0x33, 0x48, 0x2D, 0x80};
const uint8_t pubY[RIOT_COORDMAX]   = {0x9A, 0x5F, 0x2B, 0x3D, 0xF4, 0x2E, 0xA1, 0xE1, 0x5D,
                                       0xD3, 0x66, 0xCA, 0xB5, 0x99, 0x09, 0x58, 0x99, 0x8B,
                                       0x68, 0x79, 0xFA, 0xBC, 0xC9, 0x84, 0xDD, 0x30, 0x23,
                                       0xFC, 0x08, 0xB5, 0x78, 0xF2};
const uint8_t privD[RIOT_COORDMAX]  = {0xF3, 0x0F, 0x86, 0x2B, 0x66, 0xAD, 0x64, 0xF3, 0x40,
                                       0x29, 0x39, 0xC1, 0x11, 0x7C, 0x31, 0xCB, 0x56, 0x19,
                                       0xE6, 0x3E, 0xAE, 0x11, 0xF2, 0xE1, 0x1E, 0xC1, 0x19,
                                       0x9D, 0x90, 0x7F, 0x04, 0x23};
// sign
const uint8_t sigR[RIOT_COORDMAX]   = {0xBC, 0xD2, 0xAC, 0x06, 0xA4, 0x44, 0xCF, 0x23, 0xAD,
                                       0x7F, 0x39, 0xDC, 0xA5, 0xFD, 0x6E, 0xF9, 0x9F, 0x38,
                                       0xC8, 0x36, 0x98, 0x5D, 0xC8, 0x8D, 0xDD, 0x6F, 0x94,
                                       0x90, 0x8B, 0x17, 0x31, 0x91};
const uint8_t sigS[RIOT_COORDMAX]   = {0x52, 0x00, 0x9B, 0x1B, 0xB0, 0x43, 0xC9, 0xA3, 0x22,
                                       0x4A, 0xDF, 0x88, 0x18, 0x2A, 0x0D, 0x9E, 0x02, 0x98,
                                       0xB6, 0x17, 0x44, 0x58, 0xB3, 0x97, 0xF7, 0xDD, 0x79,
                                       0xF3, 0x2B, 0x74, 0x33, 0xEA};

//signdigest
const uint8_t sgdR[RIOT_COORDMAX]   = {0x40, 0x45, 0x42, 0xCF, 0xC5, 0xF6, 0x54, 0xCE, 0xC5,
                                       0xC8, 0x78, 0x55, 0xB6, 0x2C, 0xC2, 0xDA, 0xA6, 0x31,
                                       0x26, 0x8C, 0x14, 0x11, 0x27, 0xC5, 0x5D, 0x84, 0x8F,
                                       0xB1, 0x55, 0x8A, 0xC6, 0xB9};
const uint8_t sgdS[RIOT_COORDMAX]   = {0xCB, 0x5B, 0x70, 0xD7, 0xF0, 0xDE, 0x59, 0xB9, 0xBB,
                                       0xFB, 0xEA, 0xA0, 0xE1, 0x12, 0xAF, 0x19, 0x04, 0x63,
                                       0x29, 0x10, 0x11, 0x5A, 0xBB, 0xBA, 0x08, 0x5A, 0x24,
                                       0xB1, 0x5F, 0xC0, 0x3D, 0xF6};
#elif RIOT_COORDMAX == 0x30
const uint8_t pubX[RIOT_COORDMAX]   = {0x4E, 0xA4, 0xED, 0x8E, 0x31, 0x60, 0xAF, 0xF3, 0x45,
                                       0xFC, 0xA7, 0x9C, 0xE8, 0xF0, 0x4B, 0xC4, 0xFE, 0xA9,
                                       0x52, 0x85, 0xB3, 0x73, 0x9E, 0x76, 0x6A, 0xF8, 0x03,
                                       0x8C, 0xC1, 0xB1, 0x6E, 0x56, 0x84, 0xD7, 0xE2, 0x7F,
                                       0xF5, 0x94, 0x0D, 0xC7, 0x6C, 0x43, 0x70, 0x7A, 0xF7,
                                       0xB0, 0x66, 0x27};
const uint8_t pubY[RIOT_COORDMAX]   = {0x20, 0x07, 0xB7, 0xB4, 0xD0, 0xC1, 0x53, 0x63, 0x98,
                                       0xEB, 0xB8, 0x49, 0x1D, 0x5A, 0xCC, 0x0C, 0x04, 0x25,
                                       0x01, 0x1A, 0x95, 0x17, 0x84, 0x12, 0xA3, 0xCB, 0x49,
                                       0x9B, 0xF6, 0xFF, 0xB0, 0x2D, 0x33, 0x68, 0x14, 0x5C,
                                       0x1F, 0x51, 0x65, 0x98, 0x1C, 0x98, 0x2E, 0x64, 0x4A,
                                       0x1C, 0xEC, 0xE2};
const uint8_t privD[RIOT_COORDMAX]  = {0xF3, 0x0F, 0x86, 0x2B, 0x66, 0xAD, 0x64, 0xF3, 0x40,
                                       0x29, 0x39, 0xC1, 0x11, 0x7C, 0x31, 0xCB, 0x56, 0x19,
                                       0xE6, 0x3E, 0xAE, 0x11, 0xF2, 0xE1, 0x1E, 0xC1, 0x19,
                                       0x9D, 0x90, 0x7F, 0x04, 0x23, 0xBD, 0x76, 0x98, 0x94,
                                       0xC5, 0x42, 0x43, 0xD1, 0x5F, 0x47, 0x2F, 0x2F, 0xC1,
                                       0x71, 0xAD, 0xF5};
// sign
const uint8_t sigR[RIOT_COORDMAX]   = {0x49, 0x93, 0xA1, 0x1B, 0x8F, 0xD1, 0x6F, 0x30, 0xCA,
                                       0x92, 0x9F, 0x09, 0x1C, 0x33, 0x6E, 0xB5, 0x76, 0xAA,
                                       0xAC, 0x3B, 0x12, 0x44, 0xA8, 0x53, 0x52, 0xAB, 0x5F,
                                       0x3C, 0x87, 0x52, 0x98, 0x80, 0x98, 0x20, 0x8B, 0xF3,
                                       0x9A, 0x12, 0xC6, 0x69, 0x20, 0xE7, 0x20, 0x3B, 0x1F,
                                       0x36, 0x66, 0x4A};
const uint8_t sigS[RIOT_COORDMAX]   = {0xA5, 0xED, 0xDF, 0x7E, 0x7E, 0xFA, 0x06, 0x6C, 0xEB,
                                       0xAB, 0x26, 0x37, 0x0E, 0x64, 0x1F, 0x86, 0xD2, 0xF8,
                                       0x33, 0xFD, 0xF3, 0xC0, 0x07, 0x84, 0x28, 0x8E, 0xEF,
                                       0x20, 0xF1, 0xED, 0x9F, 0xC7, 0x44, 0x60, 0x5D, 0xE2,
                                       0x9B, 0x4F, 0xDB, 0x3C, 0x20, 0xE0, 0xC9, 0x9C, 0xBF,
                                       0x97, 0x13, 0x1E};
//signdigest
const uint8_t sgdR[RIOT_COORDMAX]   = {0x8D, 0xB6, 0x6F, 0x36, 0xA8, 0xC0, 0x1D, 0x13, 0xFD,
                                       0xDC, 0x95, 0xA1, 0x53, 0x5E, 0x85, 0xC8, 0x13, 0xA9,
                                       0x15, 0x5D, 0xD1, 0xC1, 0x4B, 0x92, 0x64, 0x2D, 0xB9,
                                       0x6E, 0x56, 0xB1, 0x98, 0x00, 0x9E, 0xA5, 0xCF, 0x40,
                                       0x1E, 0xE9, 0x96, 0xA1, 0x89, 0xDE, 0xA1, 0x73, 0x66,
                                       0x7D, 0xBD, 0xB6};
const uint8_t sgdS[RIOT_COORDMAX]   = {0xCD, 0xDF, 0xE1, 0xD5, 0x27, 0x8E, 0xAB, 0x9D, 0x00,
                                       0x92, 0xEE, 0xAD, 0xE2, 0x46, 0xDB, 0x43, 0xCA, 0x59,
                                       0x45, 0x87, 0x80, 0xBD, 0x74, 0xDF, 0x0E, 0x98, 0xE9,
                                       0xDD, 0x41, 0x5E, 0x4C, 0xB4, 0xA2, 0x49, 0xB2, 0x14,
                                       0x0B, 0x1D, 0xC1, 0xA6, 0x4B, 0xD2, 0xE4, 0x8A, 0x0C,
                                       0x31, 0x62, 0xAB};
#elif RIOT_COORDMAX == 0x42
const uint8_t pubX[RIOT_COORDMAX]   = {0x01, 0x92, 0x4A, 0x6C, 0x9C, 0x6A, 0x74, 0x9B, 0x3F, 0x29, 0x83, 0x63, 0x1D, 0xB3, 0x16, 0xE1, 0x8C, 0xEA, 0x1C, 0xED, 0xBA, 0xC2, 0x8C, 0x2C, 0xA5, 0xAC, 0x6C, 0xA8, 0x2C, 0xC3, 0xE0, 0x00, 0x38, 0xEA, 0x0A, 0xE3, 0x78, 0xBB, 0xB5, 0x16, 0x83, 0x53, 0x41, 0x8B, 0x3F, 0x08, 0x3D, 0x08, 0x01, 0xA7, 0x14, 0x12, 0x19, 0x0F, 0xAE, 0xA7, 0xE0, 0x4C, 0xAB, 0x76, 0x88, 0x0D, 0x42, 0xA5, 0x38, 0x72};
const uint8_t pubY[RIOT_COORDMAX]   = {0x01, 0x2C, 0x94, 0xDF, 0x80, 0x62, 0x1E, 0xA9, 0x33, 0x87, 0x57, 0x48, 0xC3, 0x4F, 0x9D, 0xBA, 0x46, 0xB5, 0x68, 0x1E, 0xA7, 0x7D, 0x1D, 0xD6, 0x91, 0x13, 0x0A, 0x6B, 0xBB, 0xE0, 0xA6, 0xEA, 0x93, 0x36, 0x88, 0xA2, 0xE0, 0x1A, 0xF6, 0xAC, 0x94, 0x7B, 0x04, 0xCE, 0xE5, 0xE7, 0x3B, 0x05, 0xB6, 0xFF, 0x4A, 0xDF, 0x4D, 0xD3, 0xE4, 0xE3, 0xA4, 0x63, 0x60, 0xFB, 0x31, 0x01, 0xF8, 0x73, 0xD8, 0xC4};
const uint8_t privD[RIOT_COORDMAX]  = {0x01, 0xE6, 0x1F, 0x0C, 0x56, 0xCD, 0x5A, 0xC9, 0xE6, 0x80, 0x52, 0x73, 0x82, 0x22, 0xF8, 0x63, 0x96, 0xAC, 0x33, 0xCC, 0x7D, 0x5C, 0x23, 0xE5, 0xC2, 0x3D, 0x82, 0x33, 0x3B, 0x20, 0xFE, 0x08, 0x47, 0x7A, 0xED, 0x31, 0x29, 0x8A, 0x84, 0x87, 0xA2, 0xBE, 0x8E, 0x5E, 0x5F, 0x82, 0xE3, 0x5B, 0xEB, 0xFB, 0x7E, 0xF7, 0xC8, 0x3F, 0xE5, 0xD9, 0x33, 0x19, 0x2E, 0x52, 0xE9, 0x44, 0x74, 0x74, 0xA3, 0x4E};
// sign
const uint8_t sigR[RIOT_COORDMAX]   = {0x00, 0x5B, 0x78, 0x6B, 0xC3, 0x76, 0x48, 0xF8, 0xF2, 0x56, 0x33, 0xC6, 0x50, 0xFB, 0xED, 0x5F, 0x2C, 0xC9, 0xDA, 0x35, 0x6F, 0x78, 0xC8, 0x78, 0x0A, 0xC7, 0x95, 0x29, 0xE5, 0xAB, 0x69, 0xDC, 0x3C, 0xC1, 0xCB, 0x35, 0xD7, 0x58, 0x1C, 0xA5, 0xD0, 0x83, 0x02, 0xF1, 0x33, 0x5E, 0x55, 0x36, 0xBE, 0xB9, 0xDA, 0x34, 0x15, 0xEC, 0x2A, 0x5A, 0x8C, 0xF1, 0x33, 0x49, 0x0E, 0xA9, 0xD8, 0x8A, 0x06, 0x42};
const uint8_t sigS[RIOT_COORDMAX]   = {0x00, 0xC6, 0x08, 0x7B, 0x91, 0x02, 0x72, 0x30, 0xDB, 0xBD, 0xAB, 0xC3, 0xC6, 0x31, 0xCF, 0x1E, 0x75, 0x57, 0x51, 0x48, 0x1A, 0x31, 0x13, 0x33, 0xCA, 0x44, 0x0A, 0x5C, 0x8A, 0xA2, 0xCB, 0x66, 0xA5, 0x69, 0xEC, 0xE7, 0xD9, 0x92, 0xE0, 0x4C, 0xF5, 0x9E, 0x17, 0x94, 0x88, 0x43, 0x9B, 0xFD, 0x7F, 0xC0, 0xA2, 0x26, 0x71, 0x8A, 0x0B, 0x42, 0xDE, 0x28, 0x04, 0x40, 0xD8, 0xAA, 0x54, 0xCC, 0xD2, 0xD9};
//signdigest
const uint8_t sgdR[RIOT_COORDMAX]   = {0x01, 0xCE, 0xB3, 0xE6, 0x4F, 0x08, 0x5B, 0x0B, 0xCF, 0xEF, 0x8B, 0xC4, 0x40, 0x5D, 0x0C, 0xB3, 0x5C, 0x29, 0xE6, 0x61, 0xD7, 0x5C, 0xED, 0xFC, 0x03, 0x88, 0x56, 0xBA, 0x3B, 0xA5, 0x7D, 0x81, 0x83, 0xC5, 0x52, 0x07, 0x21, 0xCE, 0x67, 0x24, 0xC8, 0x23, 0x08, 0x68, 0x6C, 0xF5, 0x6C, 0x0D, 0x90, 0xE5, 0x45, 0x8C, 0x8E, 0xD7, 0x5F, 0xE8, 0xF1, 0xBD, 0xA8, 0xBA, 0x9C, 0xD3, 0xA7, 0xC0, 0xD4, 0x4A};
const uint8_t sgdS[RIOT_COORDMAX]   = {0x00, 0xA1, 0x3F, 0x3C, 0x24, 0xEF, 0xC7, 0xDC, 0x03, 0x04, 0xB7, 0xB1, 0x60, 0xCD, 0x84, 0x73, 0xE0, 0x27, 0x72, 0xBA, 0x7A, 0xDA, 0xEE, 0x9D, 0xCC, 0xD9, 0x31, 0x77, 0x5C, 0xB9, 0x5A, 0xC3, 0xA9, 0xBB, 0x95, 0x94, 0x80, 0x9B, 0xF5, 0x0C, 0xE4, 0x0D, 0x25, 0x10, 0x26, 0xD8, 0x42, 0x4E, 0x34, 0x0C, 0x8E, 0x78, 0xDB, 0x93, 0x92, 0x2A, 0xC3, 0xB8, 0xF3, 0x9D, 0x95, 0x36, 0x40, 0xDD, 0xC0, 0x15};
#else
#error "Must define RIOT_COORDMAX/ECP_GRPID"
#endif

void tohex(uint8_t *bin, size_t binLen, char *str, size_t strLen);

int
main(void)
{
    uint8_t digest0[RIOT_DIGEST_LENGTH] = { 0 };
    uint8_t digest1[RIOT_DIGEST_LENGTH] = { 0 };
    uint8_t kdfbytes[42] = {0};

    // SHA1 is an "internal only" function but validate it anyway
    mbedtls_sha1_ret((uint8_t *)str0, strlen(str0), digest0);
    mbedtls_sha1_ret((uint8_t *)str1, strlen(str1), digest1);

    if (memcmp(digest0, str0_sha1, SHA1_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(digest1, str1_sha1, SHA1_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    // RiotCrypt_Hash
    printf("RiotCrypt_Hash: ");
    if(RiotCrypt_Hash(digest0, sizeof(digest0), str0, strlen(str0)))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(digest0, str0_sha256, RIOT_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    if(RiotCrypt_Hash(digest0, sizeof(digest0), str1, strlen(str1)))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(digest0, str1_sha256, RIOT_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED\n");

    // RiotCrypt_Hash2
    printf("RiotCrypt_Hash2: ");
    if(RiotCrypt_Hash2(digest0, sizeof(digest0), str0, strlen(str0), str1, strlen(str1)))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(digest0, strc_sha256, RIOT_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED\n");

    // RiotCrypt_Hmac
    printf("RiotCrypt_Hmac: ");
    if(RiotCrypt_Hmac(digest0, sizeof(digest0), str0, strlen(str0), (uint8_t *)str1, strlen(str1)))
        { printf("**%d**\n", __LINE__); goto error;}

    if(RiotCrypt_Hmac(digest1, sizeof(digest0), str0, strlen(str0), (uint8_t *)str1, strlen(str1)))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(digest0, digest1, RIOT_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED\n");

    // RiotCrypt_Hmac2
    printf("RiotCrypt_Hmac2: ");
    if(RiotCrypt_Hmac2(digest0, sizeof(digest0), str0, strlen(str0), str0_sha256, sizeof(str0_sha256), (uint8_t *)str1, strlen(str1)))
        { printf("**%d**\n", __LINE__); goto error;}

    if(RiotCrypt_Hmac2(digest1, sizeof(digest0), str0, strlen(str0), str0_sha256, sizeof(str0_sha256), (uint8_t *)str1, strlen(str1)))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(digest0, digest1, RIOT_DIGEST_LENGTH))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED\n");

    // RiotCrypt_Kdf
    printf("RiotCrypt_Kdf: ");
    if(RiotCrypt_Kdf(kdfbytes, sizeof(kdfbytes),
                     hkIKM, sizeof(hkIKM),
                     hkCtx, sizeof(hkCtx), 
                     hkInf, sizeof(hkInf),
                     sizeof(kdfbytes)))
        { printf("**%d**\n", __LINE__); goto error;}

    if (memcmp(kdfbytes, hkBTS, sizeof(hkBTS)))
        { printf("**%d**\n", __LINE__); goto error;}
        
    printf("\t\t\tPASSED\n");

    // RiotCrypt_SeedDRBG
    printf("RiotCrypt_SeedDRBG: ");
    if (RiotCrypt_SeedDRBG(str0_sha256, sizeof(str0_sha256), NULL, 0))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED\n");

    // RiotCrypt_Random
    printf("RiotCrypt_Random: ");
    if (RiotCrypt_Random(digest0, sizeof(digest0)))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED\n");

    printf("RiotCrypt_SymEncryptDecrypt: ");
    char *ptxt = "*             The per-message nonce (or information sufficient to reconstruct\n"
                 "*             it) needs to be communicated with the ciphertext and must be unique.\n"
                 "*             The recommended way to ensure uniqueness is to use a message\n"
                 "*             counter. An alternative is to generate random nonces, but this\n"
                 "*             limits the number of messages that can be securely encrypted:\n"
                 "*             for example, with 96-bit random nonces, you should not encrypt\n"
                 "*             more than 2**32 messages with the same key.\n"; 
    unsigned char out0[1024];
    unsigned char out1[1024];
    uint32_t olen = 1024;
 
    if(RiotCrypt_SymEncryptDecrypt(out0, olen, ptxt, strlen(ptxt) + 1, (uint8_t *)str0_sha256))
        { printf("**%d**\n", __LINE__); goto error;}

//  for(i = 0; i < strlen(ptxt); i++)
//  {
//      if(!(i % 37))
//          printf("\n\t");
//      printf("%02X", out0[i]);
//  }
//  printf("\n");

    if(RiotCrypt_SymEncryptDecrypt(out1, olen, out0, strlen(ptxt) + 1, (uint8_t *)str0_sha256))
        { printf("**%d**\n", __LINE__); goto error;}

//  printf("%s\n", out1);

    if(memcmp(ptxt, out1, (strlen(ptxt) + 1)))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\tPASSED\n");

    // RiotCrypt_DeriveEccKey

    RIOT_ECC_PUBLIC pub;
    RIOT_ECC_PRIVATE priv;
    uint8_t bin[RIOT_COORDMAX * 2 + 1];
    char str[1024];
    uint32_t len;
    char x[512], y[512], d[512];
    size_t size;
    char *asd = "TESTKE";

    printf("RiotCrypt_DeriveEccKey: ");
    if(RiotCrypt_DeriveEccKey(&pub, &priv, digest0, sizeof(digest0), (uint8_t *)asd, 6))
        { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&pub.X) > RIOT_COORDMAX)
       { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&pub.X, bin, RIOT_COORDMAX);
    if(memcmp(pubX, bin, RIOT_COORDMAX))
     { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&pub.Y) > RIOT_COORDMAX)
       { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&pub.Y, bin, RIOT_COORDMAX);
    if(memcmp(pubY, bin, RIOT_COORDMAX))
       { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&priv) > RIOT_COORDMAX)
        { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&priv, bin, RIOT_COORDMAX);
    if(memcmp(privD, bin, RIOT_COORDMAX))
            { printf("**%d**\n", __LINE__); goto error;}

    // Includes '\0'!
    mbedtls_mpi_write_string(&pub.X, 16, x, 512, &size);
    if((size -1) > (RIOT_COORDMAX * 2))
        { printf("**%d**\n", __LINE__); goto error;}

    // Includes '\0'!
    mbedtls_mpi_write_string(&pub.Y, 16, y, 512, &size);
    if((size -1) > (RIOT_COORDMAX * 2))
        { printf("**%d**\n", __LINE__); goto error;}

    // Includes '\0'!
    mbedtls_mpi_write_string(&priv, 16, d, 512, &size);
    if((size -1) > (RIOT_COORDMAX * 2))
        { printf("**%d**\n", __LINE__); goto error;}

#if defined(RIOTSECP256R1)
const char *c = "(SECP256R1)";
#elif defined(RIOTSECP384R1)
const char *c = "(SECP384R1)";
#elif defined(RIOTSECP521R1)
const char *c = "(SECP521R1)";
#else
#error "Must define one of RIOTSECP256R1, RIOTSECP384R1, RIOTSECP521R1"
#endif

    printf("\tPASSED %s\n", c);

    size--;

    printf("RiotCrypt_ExportEccPub: ");
    len = sizeof(bin);
    if(RiotCrypt_ExportEccPub(&pub, bin, &len))
        { printf("**%d**\n", __LINE__); goto error;}

    // tag
    if (bin[0] != 0x04)
        { printf("**%d**\n", __LINE__); goto error;}

    // bin output to hex
    tohex(&(bin[1]), RIOT_COORDMAX*2, str, 1024);
    if(memcmp(x, str, size) || memcmp(y, &str[size], size))
        { printf("**%d**\n", __LINE__); goto error;}
    printf("\tPASSED %s\n", c);

    RIOT_ECC_SIGNATURE sig0;
    printf("RiotCrypt_Sign: ");
    if(RiotCrypt_Sign(&sig0, str1, strlen(str1), &priv))
        { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&sig0.r) > RIOT_COORDMAX)
        { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&sig0.r, bin, RIOT_COORDMAX);
    if(memcmp(sigR, bin, RIOT_COORDMAX))
      { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&sig0.s) > RIOT_COORDMAX)
        { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&sig0.s, bin, RIOT_COORDMAX);
    if(memcmp(sigS, bin, RIOT_COORDMAX))
      { printf("**%d**\n", __LINE__); goto error;}

//  // Includes '\0'!
//  mbedtls_mpi_write_string(&sig0.r, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      { printf("**%d**\n", __LINE__); goto error;}
//
//  printf("r: %s\n", x);
//
//  mbedtls_mpi_write_string(&sig0.s, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      { printf("**%d**\n", __LINE__); goto error;}
//
//  printf("s: %s\n", x);
    printf("\t\tPASSED %s\n", c);

    RIOT_ECC_SIGNATURE sig1;
    printf("RiotCrypt_SignDigest: ");
    if(RiotCrypt_SignDigest(&sig1, str0_sha256, sizeof(str0_sha256), &priv))
        { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&sig1.r) > RIOT_COORDMAX)
        { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&sig1.r, bin, RIOT_COORDMAX);
    if(memcmp(sgdR, bin, RIOT_COORDMAX))
      { printf("**%d**\n", __LINE__); goto error;}

    if(mbedtls_mpi_size(&sig1.s) > RIOT_COORDMAX)
        { printf("**%d**\n", __LINE__); goto error;}

    mbedtls_mpi_write_binary(&sig1.s, bin, RIOT_COORDMAX);
    if(memcmp(sgdS, bin, RIOT_COORDMAX))
       { printf("**%d**\n", __LINE__); goto error;}

//  // Includes '\0'!
//  mbedtls_mpi_write_string(&sig1.r, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      { printf("**%d**\n", __LINE__); goto error;}
//
//  printf("r: %s\n", x);
//
//  mbedtls_mpi_write_string(&sig1.s, 16, x, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      { printf("**%d**\n", __LINE__); goto error;}
//
//  printf("s: %s\n", x);
//
//  mbedtls_mpi_write_string(&pub.Y, 16, y, 128, &size);
//  if((size -1) > (RIOT_COORDMAX * 2))
//      { printf("**%d**\n", __LINE__); goto error;}
    printf("\t\tPASSED %s\n", c);

    printf("RiotCrypt_Verify: ");
    if(RiotCrypt_Verify(str1, strlen(str1), &sig0, &pub))
        { printf("**%d**\n", __LINE__); goto error;}

    printf("\t\tPASSED %s\n", c);

    printf("RiotCrypt_VerifyDigest: ");
    if(RiotCrypt_VerifyDigest(str0_sha256, sizeof(str0_sha256), &sig1, &pub))
        { printf("**%d**\n", __LINE__); goto error;}
        
    printf("\tPASSED %s\n", c);

//  for(uint32_t i = 0; i < sizeof(kdfbytes); i++)
//      printf("%X", kdfbytes[i]);

    printf("RiotCrypt_EccEncrypt: ");
    RIOT_ECC_PUBLIC eph;
    RIOT_ECC_PUBLIC pub0;
    RIOT_ECC_PUBLIC pub1;
    RIOT_ECC_PRIVATE priv0;
    RIOT_ECC_PRIVATE priv1;
    olen = 1024;

    memset(out0, 0, sizeof(out0));
    memset(out1, 0, sizeof(out1));

    // Derive initial keypair for both parties
    if(RiotCrypt_DeriveEccKey(&pub0, &priv0, str0_sha256, sizeof(str0_sha256), NULL, 0))
        { printf("**%d**\n", __LINE__); goto error;}

    if(RiotCrypt_DeriveEccKey(&pub1, &priv1, str1_sha256, sizeof(str1_sha256), NULL, 0))
        { printf("**%d**\n", __LINE__); goto error;}

    // Sender: Encrypt using shared secret and receiver's public key
    if(RiotCrypt_EccEncrypt(out0, olen, &eph, ptxt, strlen(ptxt) + 1, &pub1))
        { printf("**%d**\n", __LINE__); goto error;}

        printf("\t\tPASSED %s\n", c);


//  for(i = 0; i < strlen(ptxt); i++)
//  {
//      if(!(i % 37))
//          fprintf(stderr, "\n\t");
//      fprintf(stderr, "%02X", out0[i]);
//  }
//  fprintf(stderr, "\n");

    printf("RiotCrypt_EccDecrypt: ");
    // Receiver: Decrypt, derived shared secret and own private key
    if(RiotCrypt_EccDecrypt(out1, olen, out0, strlen(ptxt) + 1, &eph, &priv1))
        { printf("**%d**\n", __LINE__); goto error;}

    if(memcmp(ptxt, out1, strlen(ptxt) + 1))
        { printf("**%d**\n", __LINE__); goto error;}

//  printf("%s\n", out1);

        printf("\t\tPASSED %s\n", c);

    return 0;
error:
    printf(" ***FAILED***\n");
    return -1;
}


void tohex(uint8_t *bin, size_t binLen, char *str, size_t strLen)
{
    size_t i, j;

    if ((!bin || !str) || ((binLen*2) + 1 > strLen))
        return;

    for(j = 0, i = 0; i < binLen; i++, j+=2)
        sprintf(&(str[j]), "%02X", bin[i]);

    str[j] = '\0';
    return;
}