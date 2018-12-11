/*
 * Copyright 2018 Andrej Petras.
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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import java.util.UUID;

/**
 * The treasure class tests.
 */
@RunWith(Parameterized.class)
public class TreasureTest {

    /**
     * The test parameters.
     *
     * @return the list of parameters for the test.
     */
    @Parameterized.Parameters
    public static Collection<Object> data() {
        return Arrays.asList(new Object[]{"password", "love", "1234", UUID.randomUUID().toString(), UUID.randomUUID().toString()});
    }

    /**
     * The password
     */
    private final String password;

    /**
     * The default constructor.
     *
     * @param password the password.
     */
    public TreasureTest(String password) {
        this.password = password;
    }

    /**
     * Tests the encrypt and decrypt data.
     */
    @Test
    public void createEncryptDecryptTest() {
        String secretPassword = Treasure.createSecretPassword(password.toCharArray());
        String tmp = Treasure.encrypt(password.toCharArray(), secretPassword.toCharArray());
        char[] data = Treasure.decrypt(tmp, secretPassword.toCharArray());
        Assert.assertArrayEquals(password.toCharArray(), data);
        Assert.assertEquals(password, String.copyValueOf(data));
    }

    /**
     * Test the update password method.
     */
    @Test
    public void updateSecretPasswordTest() {
        String tmp = Treasure.createSecretPassword(password.toCharArray());
        boolean verify = Treasure.verifySecretPassword(password.toCharArray(), tmp);
        Assert.assertTrue(verify);
        tmp = Treasure.updateSecretPassword(password.toCharArray(), "password".toCharArray(), tmp);
        verify = Treasure.verifySecretPassword("password".toCharArray(), tmp);
        Assert.assertTrue(verify);
    }

    /**
     * The update password method test.
     */
    @Test
    public void updateSecretPasswordTest2() {
        String tmp = Treasure.createSecretPassword(password.toCharArray());
        boolean verify = Treasure.verifySecretPassword(password.toCharArray(), tmp);
        Assert.assertTrue(verify);
        String tmp2 = Treasure.updateSecretPassword(password.toCharArray(), password.toCharArray(), tmp);
        verify = Treasure.verifySecretPassword(password.toCharArray(), tmp2);
        Assert.assertTrue(verify);
        Assert.assertEquals(tmp, tmp2);
    }

    /**
     * Test of the create secret password method.
     */
    @Test
    public void createSecretPasswordTest() {
        String tmp = Treasure.createSecretPassword(password.toCharArray());
        boolean verify = Treasure.verifySecretPassword(password.toCharArray(), tmp);
        Assert.assertTrue(verify);
    }

    /**
     * Test of the create secret password method.
     */
    @Test
    public void createSecretPasswordTest2() {
        String tmp = Treasure.createSecretPassword(password.toCharArray(), 100);
        boolean verify = Treasure.verifySecretPassword(password.toCharArray(), tmp);
        Assert.assertTrue(verify);
    }
}
