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

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * The password key.
 *
 * @author Andrej Petras
 */
@Data
@AllArgsConstructor
class PasswordKey {

    /**
     * The iterations.
     */
    private final int iterations;

    /**
     * The salt.
     */
    private final byte[] salt;

    /**
     * The key.
     */
    private final byte[] key;

}
