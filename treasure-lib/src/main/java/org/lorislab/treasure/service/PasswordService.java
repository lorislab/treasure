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
import org.lorislab.treasure.model.PasswordKey;

/**
 * The password key service.
 *
 * @author Andrej Petras
 */
public class PasswordService {

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
     * The derived key length;
     */
    private static final int DERIVED_KEY_LENGTH = 160;

    /**
     * Creates the secret password.
     *
     * @param password the password.
     * @return the corresponding secret password.
     * @throws Exception if the method fails.
     */
    public static String createSecretPassword(final String password) throws Exception {
        String result = null;

        if (password != null) {
            try {
                // create salt
                SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
                byte[] salt = new byte[8];
                random.nextBytes(salt);

                // create key
                byte[] data = createKey(password, salt, ITERATIONS);
                PasswordKey tmp = new PasswordKey(ITERATIONS, salt, data);

                return FormatService.convertPasswordKeyToString(tmp);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new Exception("Error create secret password.", ex);
            }
        }

        return result;
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

        if (password == null && secretPassword == null) {
            result = createSecretPassword(newPassword);
        } else {
            PasswordKey pk = FormatService.convertToPasswordKey(secretPassword);
            boolean valid = verifyKey(password, pk);

            if (!valid) {
                throw new Exception("The password is not valid!");
            }

            try {
                byte[] key = createKey(newPassword, pk.getSalt(), pk.getIterations());
                PasswordKey tmp = new PasswordKey(pk.getIterations(), pk.getSalt(), key);
                result = FormatService.convertPasswordKeyToString(tmp);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new Exception("Error update secret password", ex);
            }
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
        boolean result = false;

        if (password == null && secretPassword == null) {
            result = true;
        } else {
            try {
                PasswordKey tmp = FormatService.convertToPasswordKey(secretPassword);
                result = verifyKey(password, tmp);
            } catch (Exception ex) {
                throw new Exception("Error vefiry the secret password", ex);
            }
        }

        return result;
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
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, DERIVED_KEY_LENGTH);
        SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
        return f.generateSecret(spec).getEncoded();
    }

}
