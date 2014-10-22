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

import org.lorislab.treasure.api.factory.SecretKeyServiceFactory;
import org.lorislab.treasure.api.service.PasswordService;
import org.lorislab.treasure.util.PasswordUtil;

/**
 * The default password service.
 * 
 * @author Andrej Petras
 */
public class PasswordServiceImpl implements PasswordService {

    /**
     * {@inheritDoc }
     */
    @Override
    public String createPassword(char[] password) throws Exception {
        char[] key = SecretKeyServiceFactory.getService().getSecretKey();
        String result = PasswordUtil.encrypt(password, key);
        return result;
    }

    /**
     * {@inheritDoc }
     */    
    @Override
    public char[] getPassword(String data) throws Exception {
        char[] key = SecretKeyServiceFactory.getService().getSecretKey();
        char[] result = PasswordUtil.decrypt(data, key);
        return result;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean verifySecretPassword(char[] password, String secretPassword) throws Exception {
        return PasswordUtil.verifySecretPassword(password, secretPassword);
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public String createSecretPassword(char[] password) throws Exception {
        return PasswordUtil.createSecretPassword(password);
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public String updateSecretPassword(char[] password, char[] newPassword, String secretPassword) throws Exception {
        return PasswordUtil.updateSecretPassword(password, newPassword, secretPassword);
    }
    
}
