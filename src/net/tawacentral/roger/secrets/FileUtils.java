// Copyright (c) 2009, Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net.tawacentral.roger.secrets;

import au.com.bytecode.opencsv.CSVWriter;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 * Helper class to manage reading and writing the secrets file.  The file
 * is encrypted using the ciphers created by the SecurityUtils helper
 * functions.
 * 
 * Methods that touch the main secrets files are thread safe.  This allows
 * the file to be saved in a background thread so that the UI is not blocked
 * in the most common use cases.  Note that stopping the app and restarting
 * it again may still cause the UI to block if the write take a long time. 
 *
 * @author rogerta
 */
public class FileUtils {
  /** Return value for the getSaltAndRounds() function. */
  public static class SaltAndRounds {
    public SaltAndRounds(byte[] salt, int rounds) {
      this.salt = salt;
      this.rounds = rounds;
    }
    public byte[] salt;
    public int rounds;
  }

  /** Name of the secrets file. */
  public static final String SECRETS_FILE_NAME = "secrets";

  /** Name of the secrets backup file on the SD card. */
  public static final String SECRETS_FILE_NAME_SDCARD = "/sdcard/secrets";

  /** Name of the secrets CSV file on the SD card. */
  public static final String SECRETS_FILE_NAME_CSV = "/sdcard/secrets.csv";

  /** Name of the OI Safe CSV file on the SD card. */
  public static final String OI_SAFE_FILE_NAME_CSV = "/sdcard/oisafe.csv";

  private static final File SECRETS_FILE_CSV = new File(SECRETS_FILE_NAME_CSV);
  private static final File OI_SAFE_FILE_CSV = new File(OI_SAFE_FILE_NAME_CSV);

  // Secrets CSV column names
  public static final String COL_DESCRIPTION = "Description";
  public static final String COL_USERNAME = "Id";
  public static final String COL_PASSWORD = "PIN";
  public static final String COL_EMAIL = "Email";
  public static final String COL_NOTES= "Notes";

  private static final String EMPTY_STRING = "";
  private static final String INDENT = "   ";
  private static final String RP_PREFIX = "@";

  /** Tag for logging purposes. */
  public static final String LOG_TAG = "Secrets.FileUtils";

  /** Lock for accessing main secrets file. */
  private static final Object lock = new Object();

  private static final byte[] SIGNATURE = {0x22, 0x34, 0x56, 0x79};

  /**
   * Gets the salt and rounds already in use on this device, or null if none
   * exists.
   *
   * @param input The stream to read the salt and rounds from.
   *
   * @throws IOException 
   */
  public static SaltAndRounds getSaltAndRounds(InputStream input)
      throws IOException {
    // The salt is stored as a byte array at the start of the secrets file.
    byte[] signature = new byte[SIGNATURE.length];
    byte[] salt = null;
    int rounds = 0;
    input.read(signature);
    if (Arrays.equals(signature, SIGNATURE)) {
      int length = input.read();
      salt = new byte[length];
      input.read(salt);
      rounds = input.read();
      if (rounds < 4 || rounds > 31) {
        salt = null;
        rounds = 0;
      }
    }

    return new SaltAndRounds(salt, rounds);
  }


  /**
   * Opens the secrets file using the password retrieved from the user.
   * 
   * @return A list of loaded secrets.
   */
  public static ArrayList<Secret> loadSecrets(InputStream input) {
    synchronized (lock) {

      Cipher cipher = SecurityUtils.getDecryptionCipher();
      if (null == cipher)
        return null;

      ArrayList<Secret> secrets = null;

      try {
        secrets = readSecrets(input, cipher, SecurityUtils.getSalt(),
                              SecurityUtils.getRounds());
      } catch (Exception ex) {
        System.err.println("loadSecrets: " + ex);
      } finally {
        try {if (null != input) input.close();} catch (IOException ex) {}
      }

      return secrets;
    }
  }

  /**
   * Read the secrets from the given input stream, decrypting with the given
   * cipher.
   *
   * @param input The input stream to read the secrets from.
   * @param cipher The cipher to decrypt the secrets with.
   * @return The secrets read from the stream.
   * @throws IOException
   * @throws ClassNotFoundException 
   */
  @SuppressWarnings("unchecked")
  private static ArrayList<Secret> readSecrets(InputStream input,
                                               Cipher cipher,
                                               byte[] salt,
                                               int rounds)
      throws IOException, ClassNotFoundException {
    SaltAndRounds pair = getSaltAndRounds(input);
    if (!Arrays.equals(pair.salt, salt) || pair.rounds != rounds) {
      return null;
    }

    ObjectInputStream oin = new ObjectInputStream(
        new CipherInputStream(input, cipher));
    try {
      return (ArrayList<Secret>) oin.readObject();
    } finally {
      try {if (null != oin) oin.close();} catch (IOException ex) {}
    }
  }

  /**
   * Export secrets to a CSV file on the SD card.  See the description of
   * the importSecrets() method for more details about the format written.
   */
  public static boolean exportSecrets(List<Secret> secrets, CSVWriter writer) {
    // An array to hold the rows that will be written to the CSV file.
    String[] row = new String[] {
        COL_DESCRIPTION, COL_USERNAME, COL_PASSWORD, COL_EMAIL, COL_NOTES
    };
    boolean success = false;

    try {
      // Write descriptive headers.
      writer.writeNext(row);

      // Write out each secret.
      for (Secret secret : secrets) {
        row[0] = secret.getDescription();
        row[1] = secret.getUsername();
        row[2] = secret.getPassword(true);  // true: forExport
        row[3] = secret.getEmail();
        row[4] = secret.getNote();

        // NOTE: writeNext() handles nulls in row[] gracefully.
        writer.writeNext(row);
        success = true;
      }
    } catch (Exception ex) {
      System.err.println("exportSecrets: " + ex);
    } finally {
      try {if (null != writer) writer.close();} catch (IOException ex) {}
    }

    return success;
  }
}
