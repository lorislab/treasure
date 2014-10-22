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
package org.lorislab.treasure.impl.service;

import org.lorislab.treasure.api.service.SecretKeyService;

/**
 * The default secret key service implementation.
 *
 * @author Andrej Petras
 */
public class SecretKeyServiceImpl implements SecretKeyService {

    /**
     * The key system property.
     */
    private final static String PROP_KEY = "org.lorislab.treasure.secret.key";

    /**
     * The default key.
     */
    private final static char[] DEFAULT_KEY = {116, 114, 101, 97, 115, 117, 114, 101};

    /**
     * {@inheritDoc }
     */
    @Override
    public char[] getSecretKey() {
        char[] result = DEFAULT_KEY;
        String tmp = System.getProperty(PROP_KEY);
        if (tmp != null) {
            result = tmp.toCharArray();
        }
        return result;
    }

}
