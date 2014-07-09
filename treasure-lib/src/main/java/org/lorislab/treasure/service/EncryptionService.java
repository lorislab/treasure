/*
 * Copyright 2014 Andrej Petras.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.lorislab.treasure.service;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * The encryption service.
 *
 * @author Andrej Petras
 */
public class EncryptionService {

    /**
     * The algorithm for this service.
     */
    private static final String ALGORITHM = "AES";

    /**
     * The default constructor.
     */
    private EncryptionService() {
        //  empty constructor.
    }

    /**
     * Encrypts the data.
     *
     * @param data the data.
     * @param password the password for the encryption.
     * @return the corresponding encrypt data.
     * @throws Exception if the method fails.
     */
    public static String encrypt(String data, byte[] password) throws Exception {
        Key key = new SecretKeySpec(password, ALGORITHM);
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        return ConverterService.bytesToHexString(encVal);
    }

    /**
     * Decrypts the data.
     *
     * @param data the data.
     * @param password the password for the decryption.
     * @return the corresponding decrypt data.
     * @throws Exception if the method fails.
     */
    public static String decrypt(String data, byte[] password) throws Exception {
        Key key = new SecretKeySpec(password, ALGORITHM);
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = ConverterService.hexStringToBytes(data);
        byte[] decValue = c.doFinal(decordedValue);
        return new String(decValue);
    }
}
