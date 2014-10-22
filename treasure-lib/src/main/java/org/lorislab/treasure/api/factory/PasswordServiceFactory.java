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
package org.lorislab.treasure.api.factory;

import java.util.Iterator;
import java.util.ServiceLoader;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.lorislab.treasure.api.service.PasswordService;
import org.lorislab.treasure.impl.service.PasswordServiceImpl;

/**
 * The password service factory.
 *
 * @author Andrej Petras
 */
public final class PasswordServiceFactory {

    /**
     * The logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(PasswordServiceFactory.class.getName());
    /**
     * The password service.
     */
    private static PasswordService SERVICE = null;

    /**
     * Static block
     */
    static {
        PasswordService item = new PasswordServiceImpl();
        ServiceLoader<PasswordService> loader = ServiceLoader.load(PasswordService.class);
        if (loader != null) {
            Iterator<PasswordService> iter = loader.iterator();
            if (iter.hasNext()) {
                item = iter.next();
            }
        }
        SERVICE = item;
        LOGGER.log(Level.INFO, "Treasure pasword service: {0}", item.getClass().getName());
    }

    /**
     * The default constructor.
     */
    private PasswordServiceFactory() {
        // empty constructor
    }

    /**
     * Gets the password service.
     *
     * @return the password service.
     */
    public static PasswordService getService() {
        return SERVICE;
    }
}
