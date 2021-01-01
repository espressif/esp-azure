/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include <stdint.h>
#include <string.h>
#include <base64.h>

#define splitInt(intVal, bytePos) (char)((intVal >> (bytePos << 3)) & 0xFF)
#define joinChars(a, b, c, d) (uint32_t)((uint32_t)a        +   \
                                        ((uint32_t)b << 8)  +   \
                                        ((uint32_t)c << 16) +   \
                                        ((uint32_t)d << 24))
static char
base64char(
    unsigned char   Val
)
{
    if (Val < 26)
    {
        return 'A' + (char)Val;
    }
    else if (Val < 52)
    {
        return 'a' + ((char)Val - 26);
    }
    else if (Val < 62)
    {
        return '0' + ((char)Val - 52);
    }
    else if (Val == 62)
    {
        return '+';
    }
    else 
    {
        return '/';
    }
}

static char
base64b16(
    unsigned char   Val
)
{
    const uint32_t base64b16values[4] = {
        joinChars('A', 'E', 'I', 'M'),
        joinChars('Q', 'U', 'Y', 'c'),
        joinChars('g', 'k', 'o', 's'),
        joinChars('w', '0', '4', '8')
    };
    return splitInt(base64b16values[Val >> 2], (Val & 0x03));
}

static char
base64b8(
    unsigned char   Val
)
{
    const uint32_t base64b8values = joinChars('A', 'Q', 'g', 'w');
    return splitInt(base64b8values, Val);
}

static int
base64toValue(
    char             Base64Character,
    unsigned char   *Val
)
{
    int result = 0;

    if (('A' <= Base64Character) && (Base64Character <= 'Z'))
    {
        *Val = Base64Character - 'A';
    }
    else if (('a' <= Base64Character) && (Base64Character <= 'z'))
    {
        *Val = ('Z' - 'A') + 1 + (Base64Character - 'a');
    }
    else if (('0' <= Base64Character) && (Base64Character <= '9'))
    {
        *Val = ('Z' - 'A') + 1 + ('z' - 'a') + 1 + (Base64Character - '0');
    }
    else if ('+' == Base64Character)
    {
        *Val = 62;
    }
    else if ('/' == Base64Character)
    {
        *Val = 63;
    }
    else
    {
        *Val = 0;
        result = -1;
    }
    return result;
}

static uint32_t
base64CharacterCount(
    const char  *EncodedString
)
{
    uint32_t length = 0;
    unsigned char junkChar;

    while (base64toValue(EncodedString[length], &junkChar) != -1)
    {
        length++;
    }
    return length;
}

static uint32_t
Base64DecodedLength(
    const char  *EncodedString
)
// Returns the count of original bytes before being base64 encoded. Notice
// NO validation of the content of encodedString. Its length is validated
// to be a multiple of 4.
{
    uint32_t length = (uint32_t)strlen(EncodedString);
    uint32_t result;
    
    if (length == 0)
    {
        result = 0;
    }
    else
    {
        result = length / 4 * 3;
        if (EncodedString[length - 1] == '=')
        {
            if (EncodedString[length - 2] == '=')
            {
                result --;
            }
            result--;
        }
    }
    return result;
}

int
Base64Decode(
    const char      *Input,
    unsigned char   *Output,
    uint32_t        *OutLen
)
{
    uint32_t charsRemaining, reqLen;
    uint32_t encodedIndex = 0;
    uint32_t decodedIndex = 0;
    
    // Parameter validation
    if (!(Input) || !(Output) || !(OutLen)) {
        return -1;
    }

    // Validate length of source string
    if ((strlen(Input) % 4) != 0) {
        return -1;
    }

    // Validate output buffer length
    reqLen = Base64DecodedLength(Input);
    if (*OutLen < reqLen) {
        *OutLen = reqLen;
        return -1;
    }

    // Encoded character count
    charsRemaining = base64CharacterCount(Input);

    // We can only operate on individual bytes. If we attempt to work on
    // anything larger we could get an alignment fault on some architectures.
    while (charsRemaining >= 4)
    {
        unsigned char c1;
        unsigned char c2;
        unsigned char c3;
        unsigned char c4;

        (void)base64toValue(Input[encodedIndex], &c1);
        (void)base64toValue(Input[encodedIndex + 1], &c2);
        (void)base64toValue(Input[encodedIndex + 2], &c3);
        (void)base64toValue(Input[encodedIndex + 3], &c4);

        Output[decodedIndex++] = (c1 << 2) | (c2 >> 4);
        Output[decodedIndex++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
        Output[decodedIndex++] = ((c3 & 0x03) << 6) | c4;

        charsRemaining -= 4;
        encodedIndex += 4;
    }

    if (charsRemaining == 3)
    {
        unsigned char c1;
        unsigned char c2;
        unsigned char c3;

        (void)base64toValue(Input[encodedIndex], &c1);
        (void)base64toValue(Input[encodedIndex + 1], &c2);
        (void)base64toValue(Input[encodedIndex + 2], &c3);

        Output[decodedIndex++] = (c1 << 2) | (c2 >> 4);
        Output[decodedIndex] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    } 
    else if (charsRemaining == 2)
    {
        unsigned char c1;
        unsigned char c2;

        (void)base64toValue(Input[encodedIndex], &c1);
        (void)base64toValue(Input[encodedIndex + 1], &c2);

        Output[decodedIndex] = (c1 << 2) | (c2 >> 4);
    }
    return 0;
}

int
Base64Encode(
    const unsigned char *Input,
    uint32_t             Length,
    char                *Output,
    uint32_t            *OutLen
)
// The data in Input is processed 3 characters at a time to produce 4 base64
// encoded characters for as long as there are more than 3 characters still to
// process. The remaining characters (1 or 2) shall be then encoded. This
// assumes that 'a' corresponds to 0b000000 and that '_' corresponds to
// 0b111111.  It will use the optional [=] or [==] at the end of the encoded
// string, so that other less standard aware libraries can do their work.
{
    uint32_t reqSize;
    uint32_t curPos = 0;
    uint32_t dstPos = 0;

    // Parameter validation
    if (!(Input) || !(Output)) {
        return -1;
    }

    // Calculate required output buffer length in bytes
    reqSize = (Length == 0) ? (0) : ((((Length - 1) / 3) + 1) * 4);

    // Plus trailing NULL
    reqSize += 1;

    // Validate length of output buffer
    if (OutLen && (*OutLen < reqSize)) {
        *OutLen = reqSize;
        return -1;
    }

    // Perform encoding
    //   b0            b1(+1)          b2(+2)
    // 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0
    // |----c1---| |----c2---| |----c3---| |----c4---|
    while (Length - curPos >= 3)
    {
        char c1 = base64char(Input[curPos] >> 2);
        char c2 = base64char(((Input[curPos] & 3) << 4) |
                              (Input[curPos + 1] >> 4));
        char c3 = base64char(((Input[curPos + 1] & 0x0F) << 2) |
                             ((Input[curPos + 2] >> 6) & 3));
        char c4 = base64char(Input[curPos + 2] & 0x3F);

        curPos += 3;
        Output[dstPos++] = c1;
        Output[dstPos++] = c2;
        Output[dstPos++] = c3;
        Output[dstPos++] = c4;

    }

    if (Length - curPos == 2)
    {
        char c1 = base64char(Input[curPos] >> 2);
        char c2 = base64char(((Input[curPos] & 0x03) << 4) |
                              (Input[curPos + 1] >> 4));
        char c3 = base64b16(Input[curPos + 1] & 0x0F);

        Output[dstPos++] = c1;
        Output[dstPos++] = c2;
        Output[dstPos++] = c3;
        Output[dstPos++] = '=';
    }
    else if (Length - curPos == 1)
    {
        char c1 = base64char(Input[curPos] >> 2);
        char c2 = base64b8(Input[curPos] & 0x03);

        Output[dstPos++] = c1;
        Output[dstPos++] = c2;
        Output[dstPos++] = '=';
        Output[dstPos++] = '=';
    }

    // Add NL termination
    Output[dstPos] = '\n';

    // Output buffer length
    if (OutLen) {
        *OutLen = reqSize;
    }

    return 0;
}
