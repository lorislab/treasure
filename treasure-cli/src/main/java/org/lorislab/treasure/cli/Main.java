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
package org.lorislab.treasure.cli;

import org.lorislab.treasure.service.EncryptionService;
import org.lorislab.treasure.service.PasswordService;

/**
 * The main class.
 *
 * @author Andrej Petras
 */
public class Main {

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
                        create(args[1]);
                        break;
                    case "--verify":
                        verify(args[1], args[2]);
                        break;   
                    case "--update":
                        update(args[1], args[2], args[3]);
                        break; 
                    case "--encrypt":
                        encrypt(args[1], args[2]);
                        break;   
                    case "--decrypt":
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

    private static void decrypt(String password, String data) throws Exception {
        String tmp = EncryptionService.decrypt(data, password.getBytes());
        console(tmp);
    }
    
    private static void encrypt(String password, String data) throws Exception {
        String tmp = EncryptionService.encrypt(data, password.getBytes());
        console(tmp);
    }
    
    private static void update(String password, String data, String newPassword) throws Exception {
        String tmp = PasswordService.updateSecretPassword(password, newPassword, data);
        console(tmp);
    }
    
    private static void verify(String password, String data) throws Exception {
        boolean tmp = PasswordService.verifySecretPassword(password, data);
        console("" + tmp);
    }
    
    private static void create(String password) throws Exception {
        String tmp = PasswordService.createSecretPassword(password);
        console(tmp);
    }

    private static void version() {

    }

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

    private static void error(String message, Throwable ex) {
        System.err.println(message + " Error: " + ex.getMessage());
    }

    private static void console(String value) {
        System.out.println(value);
    }
}
