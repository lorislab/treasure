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
package org.lorislab.treasure.util;

import org.lorislab.treasure.util.ConverterUtil;
import org.lorislab.treasure.model.CipherKey;
import org.lorislab.treasure.model.PasswordKey;

/**
 * The format service.
 *
 * @author Andrej Petras
 */
public final class FormatUtil {

    /**
     * The default constructor.
     */
    private FormatUtil() {
        //  empty constructor.
    }

    /**
     * The secret password separator.
     */
    private static final String SEPARATOR = ":";

    /**
     * Converts the password key to secret password.
     *
     * @param passwordKey the password key.
     * @return the secret password.
     */
    public static String convertToString(final PasswordKey passwordKey) {
        StringBuilder sb = new StringBuilder();
        sb.append(passwordKey.getIterations());        
        sb.append(SEPARATOR);
        sb.append(ConverterUtil.bytesToHexString(passwordKey.getSalt()));
        sb.append(SEPARATOR);
        sb.append(ConverterUtil.bytesToHexString(passwordKey.getKey()));
        return sb.toString();
    }

    /**
     * Converts the secret password to the password key.
     *
     * @param secretPassword the secret password.
     * @return the password key.
     */
    public static PasswordKey convertToPasswordKey(final String secretPassword) {
        String[] tmp = secretPassword.split(SEPARATOR);
        int iterations = Integer.parseInt(tmp[0]);
        byte[] salt = ConverterUtil.hexStringToBytes(tmp[1]);        
        byte[] key = ConverterUtil.hexStringToBytes(tmp[2]);
        return new PasswordKey(iterations, salt, key);
    }

    /**
     * Converts the hash to the cipher key.
     *
     * @param hash the hash string.
     * @return the corresponding cipher key.
     */
    public static CipherKey convertToCipherKey(String hash) {
        String[] tmp = hash.split(SEPARATOR);
        int iterations = Integer.parseInt(tmp[0]);
        byte[] iv = ConverterUtil.hexStringToBytes(tmp[1]);
        byte[] salt = ConverterUtil.hexStringToBytes(tmp[2]);
        byte[] cipherText = ConverterUtil.hexStringToBytes(tmp[3]);
        return new CipherKey(iv, cipherText, salt, iterations);
    }

    /**
     * Converts the cipher key to the hash string.
     *
     * @param key the cipher key.
     * @return the corresponding the hash key.
     */
    public static String convertToString(final CipherKey key) {
        StringBuilder sb = new StringBuilder();
        sb.append(key.getIterations());
        sb.append(SEPARATOR);
        sb.append(ConverterUtil.bytesToHexString(key.getIv()));
        sb.append(SEPARATOR);
        sb.append(ConverterUtil.bytesToHexString(key.getSalt()));
        sb.append(SEPARATOR);
        sb.append(ConverterUtil.bytesToHexString(key.getCipherText()));
        return sb.toString();
    }
}
