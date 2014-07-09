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

import javax.xml.bind.DatatypeConverter;

/**
 * The convert service.
 * 
 * @author Andrej Petras
 */
public final class ConverterService {

    /**
     * The default constructor.
     */
    private ConverterService() {
        //  empty constructor.
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
       
}
