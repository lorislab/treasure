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
package org.lorislab.treasure;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The password key service.
 *
 * @author Andrej Petras
 */
@SuppressWarnings("WeakerAccess")
public class Treasure {

    /**
     * The main algorithm for the secret password.
     */
    private static final String ALGORITHM = "PBKDF2WithHmacSHA1";

    /**
     * The cipher algorithm.
     */
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * The key spec.
     */
    private static final String KEY_SPEC = "AES";

    /**
     * The random algorithm.
     */
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";

    /**
     * The default number of iterations.
     */
    private static final int ITERATIONS = 20000;

    /**
     * The derived key length;
     */
    private static final int DERIVED_KEY_LENGTH = 128;

    /**
     * The secret password separator.
     */
    private static final String SEPARATOR = ":";

    /**
     * Encrypts the data with the password.
     *
     * @param data     the data.
     * @param password the password.
     * @return the corresponding the data.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static String encrypt(char[] data, char[] password) {
        return encrypt(data, password, ITERATIONS);
    }

    /**
     * Encrypts the data with the password.
     *
     * @param data       the data.
     * @param password   the password.
     * @param iterations the iterations.
     * @return the corresponding the data.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static String encrypt(char[] data, char[] password, int iterations) {
        // check the data
        if (data == null) {
            return null;
        }

        try {
            // create salt
            SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
            byte[] salt = new byte[8];
            random.nextBytes(salt);

            /* Derive the key, given password and salt. */
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            KeySpec spec = new PBEKeySpec(password, salt, iterations, DERIVED_KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), KEY_SPEC);

            /* Encrypt the message. */
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            AlgorithmParameters params = cipher.getParameters();

            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            byte[] bytes = convertToByte(data);
            byte[] cipherText = cipher.doFinal(bytes);
            CipherKey key = new CipherKey(iv, cipherText, salt, iterations);

            return convertToString(key);
        } catch (Exception ex) {
            throw new RuntimeException("Error encrypt password.", ex);
        }
    }

    /**
     * Decrypts the data with password.
     *
     * @param data     the data.
     * @param password the password.
     * @return the corresponding string.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static char[] decrypt(String data, char[] password) {
        // check the data
        if (data == null) {
            return null;
        }

        try {
            CipherKey key = convertToCipherKey(data);

            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            KeySpec spec = new PBEKeySpec(password, key.getSalt(), key.getIterations(), DERIVED_KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), KEY_SPEC);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(key.getIv()));

            byte[] bytes = cipher.doFinal(key.getCipherText());
            return convertToChar(bytes);
        } catch (Exception ex) {
            throw new RuntimeException("Error decrypt password.", ex);
        }
    }

    /**
     * Creates the secret password.
     *
     * @param password the password.
     * @return the corresponding secret password.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static String createSecretPassword(final char[] password) {
        return createSecretPassword(password, ITERATIONS);
    }

    /**
     * Creates the secret password.
     *
     * @param password   the password.
     * @param iterations the iterations.
     * @return the corresponding secret password.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static String createSecretPassword(final char[] password, int iterations) {
        if (password != null) {
            try {
                // create salt
                SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
                byte[] salt = new byte[8];
                random.nextBytes(salt);

                // create key
                byte[] data = createKey(password, salt, iterations);
                PasswordKey tmp = new PasswordKey(iterations, salt, data);

                return convertToString(tmp);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new RuntimeException("Error create secret password.", ex);
            }
        }
        return null;
    }

    /**
     * Updates the secret password.
     *
     * @param password       the current password.
     * @param newPassword    the new password.
     * @param secretPassword the secret password.
     * @return the corresponding secret password.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static String updateSecretPassword(final char[] password, final char[] newPassword, final String secretPassword) {
        String result;

        if (password == null && secretPassword == null) {
            result = createSecretPassword(newPassword);
        } else {
            try {
                PasswordKey pk = convertToPasswordKey(secretPassword);
                boolean valid = verifyKey(password, pk);
                if (!valid) {
                    throw new RuntimeException("The password is not valid!");
                }

                byte[] key = createKey(newPassword, pk.getSalt(), pk.getIterations());
                PasswordKey tmp = new PasswordKey(pk.getIterations(), pk.getSalt(), key);
                result = convertToString(tmp);
            } catch (Exception ex) {
                throw new RuntimeException("Error update secret password", ex);
            }
        }

        return result;
    }

    /**
     * Verify the secret password.
     *
     * @param password       the password.
     * @param secretPassword the secret password.
     * @return returns {@code true} if the password are equals.
     * @throws RuntimeException if the method fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static boolean verifySecretPassword(final char[] password, final String secretPassword) {
        boolean result;

        if (password == null && secretPassword == null) {
            result = true;
        } else {
            try {
                PasswordKey tmp = convertToPasswordKey(secretPassword);
                result = verifyKey(password, tmp);
            } catch (Exception ex) {
                throw new RuntimeException("Error verify the secret password", ex);
            }
        }

        return result;
    }

    /**
     * Verify the password.
     *
     * @param password    the password.
     * @param passwordKey the password key.
     * @return returns {@code true} if the password are equals.
     * @throws Exception if the method fails.
     */
    private static boolean verifyKey(final char[] password, final PasswordKey passwordKey) throws Exception {
        byte[] tmp = createKey(password, passwordKey.getSalt(), passwordKey.getIterations());
        return Arrays.equals(tmp, passwordKey.getKey());
    }

    /**
     * Creates the key as an array of bytes.
     *
     * @param password   the password string.
     * @param salt       the salt.
     * @param iterations the number of iterations.
     * @return the key as an array of bytes.
     * @throws NoSuchAlgorithmException if the method fails.
     * @throws InvalidKeySpecException  if the method fails.
     */
    private static byte[] createKey(final char[] password, byte[] salt, int iterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, DERIVED_KEY_LENGTH);
        SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
        return f.generateSecret(spec).getEncoded();
    }

    /**
     * Converts the array of characters to array of byte.
     *
     * @param data the array of characters.
     * @return the corresponding array of the bytes.
     */
    private static byte[] convertToByte(char[] data) {
        CharBuffer charBuffer = CharBuffer.wrap(data);
        ByteBuffer byteBuffer = Charset.forName(StandardCharsets.UTF_8.name()).encode(charBuffer);
        byte[] result = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(charBuffer.array(), '\u0000');
        Arrays.fill(byteBuffer.array(), (byte) 0);
        return result;
    }

    /**
     * Converts the array of bytes to array of characters.
     *
     * @param data the array of bytes.
     * @return the corresponding array of the characters.
     */
    private static char[] convertToChar(byte[] data) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        CharBuffer charBuffer = Charset.forName(StandardCharsets.UTF_8.name()).decode(byteBuffer);
        char[] result = Arrays.copyOfRange(charBuffer.array(), charBuffer.position(), charBuffer.limit());
        Arrays.fill(charBuffer.array(), '\u0000');
        Arrays.fill(byteBuffer.array(), (byte) 0);
        return result;
    }

    /**
     * Converts the password key to secret password.
     *
     * @param passwordKey the password key.
     * @return the secret password.
     */
    private static String convertToString(final PasswordKey passwordKey) {
        return "" + passwordKey.getIterations() + SEPARATOR + b2hex(passwordKey.getSalt()) + SEPARATOR + b2hex(passwordKey.getKey());
    }

    /**
     * Converts the secret password to the password key.
     *
     * @param secretPassword the secret password.
     * @return the password key.
     */
    private static PasswordKey convertToPasswordKey(final String secretPassword) {
        String[] tmp = secretPassword.split(SEPARATOR);
        int iterations = Integer.parseInt(tmp[0]);
        byte[] salt = hex2b(tmp[1]);
        byte[] key = hex2b(tmp[2]);
        return new PasswordKey(iterations, salt, key);
    }

    /**
     * Converts the hash to the cipher key.
     *
     * @param hash the hash string.
     * @return the corresponding cipher key.
     */
    private static CipherKey convertToCipherKey(String hash) {
        String[] tmp = hash.split(SEPARATOR);
        int iterations = Integer.parseInt(tmp[0]);
        byte[] iv = hex2b(tmp[1]);
        byte[] salt = hex2b(tmp[2]);
        byte[] cipherText = hex2b(tmp[3]);
        return new CipherKey(iv, cipherText, salt, iterations);
    }

    /**
     * Converts the cipher key to the hash string.
     *
     * @param key the cipher key.
     * @return the corresponding the hash key.
     */
    private static String convertToString(final CipherKey key) {
        return "" + key.getIterations() + SEPARATOR + b2hex(key.getIv()) + SEPARATOR + b2hex(key.getSalt()) + SEPARATOR + b2hex(key.getCipherText());
    }

    /**
     * Converts an array of bytes into a string.
     *
     * @param array the array of bytes.
     * @return the string.
     */
    private static String b2hex(byte[] array) {
        StringBuilder sb = new StringBuilder();
        for (byte b : array) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Converts the string argument into an array of bytes.
     *
     * @param hexString the string.
     * @return the array of bytes.
     */
    private static byte[] hex2b(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return bytes;
    }
}
