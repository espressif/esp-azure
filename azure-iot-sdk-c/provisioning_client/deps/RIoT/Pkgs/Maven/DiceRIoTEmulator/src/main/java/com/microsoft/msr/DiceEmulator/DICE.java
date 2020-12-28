/*
 *
 *  Copyright (c) Microsoft. All rights reserved.
 *  Licensed under the MIT license. See LICENSE file in the project root for full license information.
 *
 */
package com.microsoft.msr.DiceEmulator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The DICE class is used to emulate DICE-enabled hardware. It is a dependency
 * of the RIoT emulator. The RIoT emulator is used to create keys and certificates
 * for identification and attestation of Azure IoT devices. The emulator can be
 * used for developing solutions on platforms that do not have DiceEmulator hardware, or
 * can be used to create a software-only asymmetric-key based device identity (with
 * no hardware protection for the keys).
 */
public class DICE {
    /**
     * Hashing function for DICE emulation (SHA256)
     *
     * @param buf Byte buffer from which digest is computed
     * @return Digest of 'buf'
     * @throws NoSuchAlgorithmException When no "SHA-256"
     */
    public static byte[] DiceSHA256(byte[] buf)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buf);
        return md.digest();
    }

    /**
     * Hashing function for DICE emulation (SHA256)
     *
     * @param buf1 First byte buffer to be included in digest
     * @param buf2 Second byte buffer to be included in digest
     * @return Digest of 'buf1' and 'buf2'
     * @throws NoSuchAlgorithmException When no "SHA-256"
     */
    public static byte[] DiceSHA256(byte[] buf1, byte[] buf2)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buf1);
        md.update(buf2);
        return md.digest();
    }
}
