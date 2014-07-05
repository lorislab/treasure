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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.lorislab.treasure.model.PasswordKey;

/**
 * The password key service.
 *
 * @author Andrej Petras
 */
public class PasswordKeyService {

    /**
     * The main algorithm for the secret password.
     */
    private static final String ALGORITHM = "PBKDF2WithHmacSHA1";

    /**
     * The random algorithm.
     */
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";

    /**
     * The default number of iterations.
     */
    private static final int ITERATIONS = 20000;

    /**
     * The secret password separator.
     */
    private static final String SEPARATOR = ":";

    /**
     * Creates the secret password.
     *
     * @param password the password.
     * @return the corresponding secret password.
     * @throws Exception if the method fails.
     */
    public static String createSecretPassword(final String password) throws Exception {
        try {
            PasswordKey tmp = createPasswordKey(password);
            return convertPasswordKeyToString(tmp);
        } catch (Exception ex) {
            throw new Exception("Error create secret password.", ex);
        }
    }

    /**
     * Updates the secret password.
     *
     * @param password the current password.
     * @param newPassword the new password.
     * @param secretPassword the secret password.
     * @return the corresponding secret password.
     * @throws Exception if the method fails.
     */
    public static String updateSecretPassword(final String password, final String newPassword, final String secretPassword) throws Exception {
        String result = null;
        try {
            PasswordKey pk = convertToPasswordKey(secretPassword);
            boolean valid = verifyKey(password, pk);
            if (valid) {
                byte[] key = createKey(newPassword, pk.getSalt(), pk.getIterations());
                PasswordKey tmp = new PasswordKey(pk.getIterations(), pk.getSalt(), key);
                result = convertPasswordKeyToString(tmp);
            }
        } catch (Exception ex) {
            throw new Exception("Error update secret password", ex);
        }

        if (result == null) {
            throw new Exception("The current password is not valid");
        }

        return result;
    }

    /**
     * Verify the secret password.
     *
     * @param password the password.
     * @param secretPassword the secret password.
     * @return returns {@code true} if the password are equals.
     * @throws Exception if the method fails.
     */
    public static boolean verifySecretPassword(final String password, final String secretPassword) throws Exception {
        try {
            PasswordKey tmp = convertToPasswordKey(secretPassword);
            return verifyKey(password, tmp);
        } catch (Exception ex) {
            throw new Exception("Error vefiry the secret password", ex);
        }
    }

    /**
     * Creates the password key.
     *
     * @param password the password.
     * @return the corresponding password key.
     * @throws Exception if the method fails.
     */
    private static PasswordKey createPasswordKey(final String password) throws Exception {
        byte[] salt = createSalt();
        byte[] tmp = createKey(password, salt, ITERATIONS);
        return new PasswordKey(ITERATIONS, salt, tmp);
    }

    /**
     * Converts the password key to secret password.
     *
     * @param passwordKey the password key.
     * @return the secret password.
     */
    private static String convertPasswordKeyToString(final PasswordKey passwordKey) {
        StringBuilder sb = new StringBuilder();
        sb.append(bytesToHexString(passwordKey.getSalt()));
        sb.append(SEPARATOR);
        sb.append(passwordKey.getIterations());
        sb.append(SEPARATOR);
        sb.append(bytesToHexString(passwordKey.getKey()));
        return sb.toString();
    }

    /**
     * Converts the secret password to the password key.
     *
     * @param secretPassword the secret password.
     * @return the password key.
     */
    private static PasswordKey convertToPasswordKey(final String secretPassword) {
        String[] tmp = secretPassword.split(SEPARATOR);
        byte[] salt = hexStringToBytes(tmp[0]);
        int iterations = Integer.parseInt(tmp[1]);
        byte[] key = hexStringToBytes(tmp[2]);
        return new PasswordKey(iterations, salt, key);
    }

    /**
     * Verify the password.
     *
     * @param password the password.
     * @param passwordKey the password key.
     * @return returns {@code true} if the password are equals.
     * @throws Exception if the method fails.
     */
    private static boolean verifyKey(final String password, final PasswordKey passwordKey) throws Exception {
        byte[] tmp = createKey(password, passwordKey.getSalt(), passwordKey.getIterations());
        return Arrays.equals(tmp, passwordKey.getKey());
    }

    /**
     * Creates the key as an array of bytes.
     *
     * @param password the password string.
     * @param salt the salt.
     * @param iterations the number of iterations.
     * @return the key as an array of bytes.
     * @throws NoSuchAlgorithmException if the method fails.
     * @throws InvalidKeySpecException if the method fails.
     */
    private static byte[] createKey(final String password, byte[] salt, int iterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int derivedKeyLength = 160;
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);
        SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
        return f.generateSecret(spec).getEncoded();
    }

    /**
     * Creates the salt.
     *
     * @return the corresponding salt.
     * @throws NoSuchAlgorithmException if the method fails.
     */
    private static byte[] createSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Converts an array of bytes into a string.
     *
     * @param array the array of bytes.
     * @return the string.
     */
    public static String bytesToHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    /**
     * Converts the string argument into an array of bytes.
     *
     * @param s the string.
     * @return the array of bytes.
     */
    public static byte[] hexStringToBytes(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

//    private static String bytesToHexString(byte[] bytes) {
//        StringBuilder sb = new StringBuilder();
//        for (byte b : bytes) {
//            sb.append(String.format("%02x", b & 0xff));
//        }
//        return sb.toString();
//    }
//
//    private static byte[] hexStringToBytes(String s) {
//        int len = s.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
//                    + Character.digit(s.charAt(i + 1), 16));
//        }
//        return data;
//    }    
}
