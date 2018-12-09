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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * The main class.
 *
 * @author Andrej Petras
 */
public class TreasureMain {

    /**
     * The MAVEN properties path.
     */
    private static final String MAVEN_PROPS = "/META-INF/maven/org.lorislab.treasure/treasure-cli/pom.properties";

    /**
     * The MAVEN version key.
     */
    private static final String MAVEN_KEY = "version";

    /**
     * The main method.
     *
     * @param args the list of arguments.
     */
    public static final void main(String... args) {

        if (args == null || args.length == 0) {
            help();
        } else {
            String cmd = args[0];
            try {
                switch (cmd) {
                    case "--create":
                        check(args, 2);
                        create(args[1]);
                        break;
                    case "--verify":
                        check(args, 3);
                        verify(args[1], args[2]);
                        break;
                    case "--update":
                        check(args, 4);
                        update(args[1], args[2], args[3]);
                        break;
                    case "--encrypt":
                        check(args, 3);
                        encrypt(args[1], args[2]);
                        break;
                    case "--decrypt":
                        check(args, 3);
                        decrypt(args[1], args[2]);
                        break;
                    case "--version":
                        version();
                        break;
                    case "--help":
                        help();
                        break;
                }
            } catch (Exception ex) {
                error("Error execute the command " + cmd, ex);
            }
        }
    }

    /**
     * Decrypts the data with password.
     *
     * @param password the password.
     * @param data the hash data.
     * @throws Exception if the method fails.
     */
    private static void decrypt(String password, String data) throws Exception {
        char[] tmp = Treasure.decrypt(data, password.toCharArray());
        console(new String(tmp));
    }

    /**
     * Encrypts the data with password.
     *
     * @param password the password.
     * @param data the data.
     * @throws Exception if the method fails.
     */
    private static void encrypt(String password, String data) throws Exception {
        String tmp = Treasure.encrypt(data.toCharArray(), password.toCharArray());
        console(tmp);
    }

    /**
     * Updates the password.
     *
     * @param password the old password.
     * @param data the hash data.
     * @param newPassword the new password.
     * @throws Exception if the method fails.
     */
    private static void update(String password, String data, String newPassword) throws Exception {
        String tmp = Treasure.updateSecretPassword(password.toCharArray(), newPassword.toCharArray(), data);
        console(tmp);
    }

    /**
     * Verify the password.
     *
     * @param password the password.
     * @param data the hash data.
     * @throws Exception if the method fails.
     */
    private static void verify(String password, String data) throws Exception {
        boolean tmp = Treasure.verifySecretPassword(password.toCharArray(), data);
        console("" + tmp);
    }

    /**
     * Creates the password hash.
     *
     * @param password the password.
     * @throws Exception if the method fails.
     */
    private static void create(String password) throws Exception {
        String tmp = Treasure.createSecretPassword(password.toCharArray());
        console(tmp);
    }

    /**
     * Print out the version.
     */
    private static void version() {
        Properties properties = new Properties();
        try {
            try (InputStream in = TreasureMain.class.getResourceAsStream(MAVEN_PROPS)) {
                properties.load(in);
            }
        } catch (IOException ex) {
            // do nothing
        }
        console("Version: " + properties.getProperty(MAVEN_KEY));
    }

    /**
     * Print out the help.
     */
    private static void help() {
        console("Usage: treasure-cli <command> <values>");
        console("--create  <password>");
        console("--verify  <password> <hash>");
        console("--update  <password> <newPassword> <hash>");
        console("--encrypt <password> <data>");
        console("--decrypt <password> <hash>");
        console("--version");
        console("--help");
    }

    /**
     * Checks the number of the parameters.
     *
     * @param args the list of arguments.
     * @param length the length.
     * @throws Exception if the method fails.
     */
    private static void check(String[] args, int length) throws Exception {
        if (args == null || args.length != length) {
            throw new Exception("Wrong number of parameters!");
        }
    }

    /**
     * Print out the error.
     *
     * @param message the message.
     * @param ex the exception.
     */
    private static void error(String message, Throwable ex) {
        System.err.println(message + " Error: " + ex.getMessage());
    }

    /**
     * Print out the value in to the console.
     *
     * @param value the value.
     */
    private static void console(String value) {
        System.out.println(value);
    }
}
