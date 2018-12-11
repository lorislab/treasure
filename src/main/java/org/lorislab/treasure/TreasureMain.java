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

import java.io.InputStream;
import java.io.PrintStream;
import java.util.Properties;

/**
 * The main class.
 *
 * @author Andrej Petras
 */
public class TreasureMain {

    /**
     * The system output.
     */
    private static final PrintStream CONSOLE = System.out;

    /**
     * The main method.
     *
     * @param args the list of arguments.
     */
    public static void main(String... args) {

        if (args == null || args.length == 0) {
            help();
        } else {
            String cmd = args[0];
            try {
                switch (cmd) {
                    case "--create":
                        check(args, 2);
                        String tmp = Treasure.createSecretPassword(args[1].toCharArray());
                        CONSOLE.println(tmp);
                        break;
                    case "--verify":
                        check(args, 3);
                        boolean verify = Treasure.verifySecretPassword(args[1].toCharArray(), args[2]);
                        CONSOLE.println("" + verify);
                        break;
                    case "--update":
                        check(args, 4);
                        String update = Treasure.updateSecretPassword(args[1].toCharArray(), args[3].toCharArray(), args[2]);
                        CONSOLE.println(update);
                        break;
                    case "--encrypt":
                        check(args, 3);
                        String encrypt = Treasure.encrypt(args[1].toCharArray(), args[2].toCharArray());
                        CONSOLE.println(encrypt);
                        break;
                    case "--decrypt":
                        check(args, 3);
                        char[] decrypt = Treasure.decrypt(args[1], args[2].toCharArray());
                        CONSOLE.println(new String(decrypt));
                        break;
                    case "--version":
                        Properties properties = new Properties();
                        try (InputStream in = TreasureMain.class.getResourceAsStream("/META-INF/maven/org.lorislab.treasure/treasure/pom.properties")) {
                            properties.load(in);
                        }
                        CONSOLE.println("Version: " + properties.getProperty("version"));
                        break;
                    case "--help":
                        help();
                        break;
                }
            } catch (Exception ex) {
                System.err.println("Error execute the command Error: " + ex.getMessage());
            }
        }
    }

    /**
     * Print out the help.
     */
    private static void help() {
        CONSOLE.println("Usage: treasure-cli <command> <values>");
        CONSOLE.println("--create  <password>");
        CONSOLE.println("--verify  <password> <hash>");
        CONSOLE.println("--update  <password> <newPassword> <hash>");
        CONSOLE.println("--encrypt <password> <data>");
        CONSOLE.println("--decrypt <password> <hash>");
        CONSOLE.println("--version");
        CONSOLE.println("--help");
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

}
