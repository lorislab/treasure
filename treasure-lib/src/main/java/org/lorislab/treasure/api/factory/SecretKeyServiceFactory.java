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
import org.lorislab.treasure.api.service.SecretKeyService;
import org.lorislab.treasure.impl.service.SecretKeyServiceImpl;

/**
 * The secret key service factory.
 *
 * @author Andrej Petras
 */
public class SecretKeyServiceFactory {

    /**
     * The logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(SecretKeyServiceFactory.class.getName());
    
    /**
     * The password service.
     */
    private static SecretKeyService SERVICE = null;

    /**
     * Static block
     */
    static {
        SecretKeyService item = new SecretKeyServiceImpl();
        
        ServiceLoader<SecretKeyService> loader = ServiceLoader.load(SecretKeyService.class);
        if (loader != null) {
            Iterator<SecretKeyService> iter = loader.iterator();
            if (iter.hasNext()) {
                item = iter.next();                                
            }
        }
        SERVICE = item;
        LOGGER.log(Level.INFO, "Treasure secret key service: {0}", item.getClass().getName());
    }

    /**
     * The default constructor.
     */
    public SecretKeyServiceFactory() {
        // empty constructor
    }

    /**
     * Gets the secret key service.
     *
     * @return the secret key service.
     */
    public static SecretKeyService getService() {
        return SERVICE;
    }
}
