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
package org.lorislab.treasure.api.service;

/**
 * The password service.
 *
 * @author Andrej Petras
 */
public interface PasswordService {

    /**
     * Verifies the secret password.
     *
     * @param password the input password.
     * @param secretPassword the secret password.
     * @return {@code true} if the input password is same the secret password.
     * @throws Exception if the method fails.
     */
    public boolean verifySecretPassword(final char[] password, final String secretPassword) throws Exception;

    /**
     * Creates the secret password.
     *
     * @param password the password.
     * @return the secret password.
     *
     * @throws java.lang.Exception if the method fails.
     */
    public String createSecretPassword(final char[] password) throws Exception;

    /**
     * Updates the secret password.
     *
     * @param password the current password.
     * @param newPassword the new password.
     * @param secretPassword the secret password.
     * @return the new created secret password.
     * @throws Exception if the method fails.
     */
    public String updateSecretPassword(final char[] password, final char[] newPassword, final String secretPassword) throws Exception;

    /**
     * Creates the password.
     *
     * @param password the password.
     * @return the secret password.
     *
     * @throws java.lang.Exception if the method fails.
     */
    public String createPassword(char[] password) throws Exception;

    /**
     * Gets the password from secret password.
     *
     * @param data the secret password.
     * @return the plain password.
     *
     * @throws java.lang.Exception if the method fails.
     */
    public char[] getPassword(String data) throws Exception;
}
