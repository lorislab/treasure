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

import org.lorislab.treasure.model.PasswordKey;

/**
 * The format service.
 * 
 * @author Andrej Petras
 */
public final class FormatService {
    
    /**
     * The default constructor.
     */    
    private FormatService() {
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
    public static String convertPasswordKeyToString(final PasswordKey passwordKey) {
        StringBuilder sb = new StringBuilder();
        sb.append(ConverterService.bytesToHexString(passwordKey.getSalt()));
        sb.append(SEPARATOR);
        sb.append(passwordKey.getIterations());
        sb.append(SEPARATOR);
        sb.append(ConverterService.bytesToHexString(passwordKey.getKey()));
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
        byte[] salt = ConverterService.hexStringToBytes(tmp[0]);
        int iterations = Integer.parseInt(tmp[1]);
        byte[] key = ConverterService.hexStringToBytes(tmp[2]);
        return new PasswordKey(iterations, salt, key);
    }    
}
