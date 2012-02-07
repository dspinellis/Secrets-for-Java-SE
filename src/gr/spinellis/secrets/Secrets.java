// Copyright (c) 2012, Diomidis Spinellis
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

package gr.spinellis.secrets;

import au.com.bytecode.opencsv.CSVWriter;

import java.io.BufferedWriter;
import java.io.Console;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.io.Writer;
import java.nio.channels.Channels;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import net.tawacentral.roger.secrets.FileUtils;
import net.tawacentral.roger.secrets.FileUtils.SaltAndRounds;
import net.tawacentral.roger.secrets.SecurityUtils.CipherInfo;
import net.tawacentral.roger.secrets.Secret;
import net.tawacentral.roger.secrets.SecurityUtils;

// http://www.bouncycastle.org/latest_releases.html
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Class to provide a command-line interface for decoding Google's
 * secrets-for-android files.
 * See http://code.google.com/p/secrets-for-android/
 *
 * @author Diomidis Spinellis
 */
public class Secrets {
    public static void main(String args[]) {
	// Verify arguments
	if (args.length != 2) {
	    System.err.println("Usage: secrets inputfile outputfile");
	    System.exit(1);
	}

	// Verify console
	Console cons = System.console();
	if (cons == null) {
	    System.err.println("No console to read password from");
	    System.exit(1);
	}

	// Open seekable input stream
	RandomAccessFile rInput = null;
	try {
	    rInput = new RandomAccessFile(args[0], "r");
	} catch (java.io.FileNotFoundException ex) {
	    System.err.println("Unable to open input file " + args[0] + ": " + ex);
	    System.exit(1);
	}
	InputStream input = Channels.newInputStream(rInput.getChannel());

	// Open output file
	CSVWriter writer = null;
	try {
	    writer = new CSVWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(args[1]), "UTF-8")));
	} catch (java.io.UnsupportedEncodingException ex) {
	    System.err.println("Unable to properly encode output file: " + ex);
	    System.exit(1);
	} catch (java.io.FileNotFoundException ex) {
	    System.err.println("Unable to open output file " + args[1] + ": " + ex);
	    System.exit(1);
	}

	Security.addProvider(new BouncyCastleProvider());
	SaltAndRounds pair = null;
	try {
	    pair = FileUtils.getSaltAndRounds(input);
	} catch (java.io.IOException ex) {
	    System.err.println("Unable to seek to read encryption properties from the input file " + args[0] + ": " + ex);
	    System.exit(1);
	}
	char[] pass = cons.readPassword("Enter password:");
	SecurityUtils.saveCiphers(SecurityUtils.createCiphers(new String(pass),
						    pair.salt,
						    pair.rounds));
	try {
	    rInput.seek(0);
	} catch (java.io.IOException ex) {
	    System.err.println("Unable to seek to the beginning of input file " + args[0] + ": " + ex);
	    System.exit(1);
	}

	ArrayList<Secret> s = FileUtils.loadSecrets(input);
	if (s == null) {
	    System.err.println("Unable to read secrets from " + args[0]);
	    System.exit(1);
	}
	FileUtils.exportSecrets(s, writer);
	System.exit(0);
    }
}
