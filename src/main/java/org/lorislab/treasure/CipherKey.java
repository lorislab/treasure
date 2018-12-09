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

/**
 * The cipher key.
 *
 * @author Andrej Petras
 */
public class CipherKey {

    /**
     * The iv.
     */
    private final byte[] iv;

    /**
     * The cipher test.
     */
    private final byte[] cipherText;

    /**
     * The salt.
     */
    private final byte[] salt;

    /**
     * The iterations.
     */
    private final int iterations;
    
    /**
     * The default constructor.
     *
     * @param iv the iv.
     * @param cipherText the cipher text.
     * @param salt the salt.
     * @param iterations the iterations.
     */
    public CipherKey(byte[] iv, byte[] cipherText, byte[] salt, int iterations) {
        this.iv = iv;
        this.cipherText = cipherText;
        this.salt = salt;
        this.iterations = iterations;
    }

    /**
     * Gets the iterations.
     *
     * @return the iterations.
     */
    public int getIterations() {
        return iterations;
    }
    
    /**
     * Gets the iv.
     *
     * @return the iv.
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * The cipher text.
     *
     * @return the cipher text.
     */
    public byte[] getCipherText() {
        return cipherText;
    }

    /**
     * Gets the salt.
     *
     * @return the salt.
     */
    public byte[] getSalt() {
        return salt;
    }

}
