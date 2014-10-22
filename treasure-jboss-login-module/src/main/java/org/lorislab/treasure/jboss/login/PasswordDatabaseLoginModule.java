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
package org.lorislab.treasure.jboss.login;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.jboss.security.auth.spi.DatabaseServerLoginModule;
import org.lorislab.treasure.util.PasswordUtil;

/**
 * The database login module.
 *
 * @author Andrej Petras
 */
public class PasswordDatabaseLoginModule extends DatabaseServerLoginModule {

    /**
     * The logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(PasswordDatabaseLoginModule.class.getName());
    
    /**
     * Validates the password by password service.
     *
     * @param inputPassword the input password.
     * @param expectedPassword the database password.
     * @return {@code true} if the password are equals.
     */
    @Override
    protected boolean validatePassword(String inputPassword, String expectedPassword) {
        boolean result = false;
        char[] tmp = null;
        if (inputPassword != null) {
            tmp = inputPassword.toCharArray();
        }
        try {
            result = PasswordUtil.verifySecretPassword(tmp, expectedPassword);
        } catch (Exception ex) {
            LOGGER.log(Level.FINEST, "Verify secret password failed!", ex);
            LOGGER.log(Level.FINER, "Bad password for the username {0}", getUsername());
        }
        return result;
    }

}
