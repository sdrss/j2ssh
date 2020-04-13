/*
 *  SSHTools - Java SSH2 API
 *
 *  Copyright (C) 2002-2003 Lee David Painter and Contributors.
 *
 *  Contributions made by:
 *
 *  Brett Smith
 *  Richard Pernavas
 *  Erwin Bolwidt
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package com.sshtools.j2ssh.transport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.StringTokenizer;

import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.configuration.SshConnectionProperties;
import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.io.ByteArrayWriter;
import com.sshtools.j2ssh.transport.cipher.SshCipherFactory;
import com.sshtools.j2ssh.transport.compression.SshCompressionFactory;
import com.sshtools.j2ssh.transport.hmac.SshHmacFactory;
import com.sshtools.j2ssh.transport.kex.SshKeyExchangeFactory;
import com.sshtools.j2ssh.transport.publickey.SshKeyPairFactory;

/**
 * @author $author$
 * @version $Revision: 1.25 $
 */
public class SshMsgKexInit extends SshMessage {
	/**  */
	protected final static int SSH_MSG_KEX_INIT = 20;
	private List<String> supportedCompCS;
	private List<String> supportedCompSC;
	private List<String> supportedEncryptCS;
	private List<String> supportedEncryptSC;
	private List<String> supportedKex;
	private List<String> supportedLangCS;
	private List<String> supportedLangSC;
	private List<String> supportedMacCS;
	private List<String> supportedMacSC;
	private List<String> supportedPK;
	
	// Message values
	private byte[] cookie;
	private boolean firstKexFollows;
	
	/**
	 * Creates a new SshMsgKexInit object.
	 */
	public SshMsgKexInit() {
		super(SSH_MSG_KEX_INIT);
	}
	
	/**
	 * Creates a new SshMsgKexInit object.
	 *
	 * @param props
	 */
	public SshMsgKexInit(SshConnectionProperties props) {
		super(SSH_MSG_KEX_INIT);
		
		// Create some random data
		cookie = new byte[16];
		
		// Seed the random number generator
		Random r = ConfigurationLoader.getRND();
		
		// Get the next random bytes into our cookie
		r.nextBytes(cookie);
		
		// Get the supported algorithms from the factory objects but adding the
		// preferred algorithm to the top of the list
		supportedKex = sortAlgorithmList(SshKeyExchangeFactory.getSupportedKeyExchanges(),
				props.getPrefKex());
		supportedPK = sortAlgorithmList(SshKeyPairFactory.getSupportedKeys(),
				props.getPrefPublicKey());
		supportedEncryptCS = sortAlgorithmList(SshCipherFactory.getSupportedCiphers(),
				props.getPrefCSEncryption());
		supportedEncryptSC = sortAlgorithmList(SshCipherFactory.getSupportedCiphers(),
				props.getPrefSCEncryption());
		supportedMacCS = sortAlgorithmList(SshHmacFactory.getSupportedMacs(),
				props.getPrefCSMac());
		supportedMacSC = sortAlgorithmList(SshHmacFactory.getSupportedMacs(),
				props.getPrefSCMac());
		supportedCompCS = sortAlgorithmList(SshCompressionFactory.getSupportedCompression(),
				props.getPrefCSComp());
		supportedCompSC = sortAlgorithmList(SshCompressionFactory.getSupportedCompression(),
				props.getPrefSCComp());
		
		// We currently don't support language preferences
		supportedLangCS = new ArrayList<String>();
		supportedLangSC = new ArrayList<String>();
		
		// We don't guess (I don't see the point of this in the protocol!)
		firstKexFollows = false;
	}
	
	/**
	 * @return
	 */
	@Override
	public String getMessageName() {
		return "SSH_MSG_KEX_INIT";
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedCSComp() {
		return supportedCompCS;
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedCSEncryption() {
		return supportedEncryptCS;
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedCSMac() {
		return supportedMacCS;
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedKex() {
		return supportedKex;
	}
	
	/**
	 * @param pks
	 */
	public void setSupportedPK(List<String> pks) {
		supportedPK.clear();
		supportedPK.addAll(pks);
		sortAlgorithmList(supportedPK, SshKeyPairFactory.getDefaultPublicKey());
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedPublicKeys() {
		return supportedPK;
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedSCComp() {
		return supportedCompSC;
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedSCEncryption() {
		return supportedEncryptSC;
	}
	
	/**
	 * @return
	 */
	public List<String> getSupportedSCMac() {
		return supportedMacSC;
	}
	
	/**
	 * @param list
	 * @return
	 */
	public String createDelimString(List<String> list) {
		// Set up the separator (blank to start cause we don't want a comma
		// at the beginning of the list)
		String sep = "";
		String ret = "";
		
		// Iterate through the list
		for (final String elem : list) {
			// Add the separator and then the item
			ret += (sep + elem);
			sep = ",";
		}
		
		return ret;
	}
	
	/**
	 * @return
	 */
	@Override
	public String toString() {
		String ret = "SshMsgKexInit:\n";
		ret += ("Supported Kex " + supportedKex.toString() + "\n");
		ret += ("Supported Public Keys " + supportedPK.toString() + "\n");
		ret += ("Supported Encryption Client->Server " +
				supportedEncryptCS.toString() + "\n");
		ret += ("Supported Encryption Server->Client " +
				supportedEncryptSC.toString() + "\n");
		ret += ("Supported Mac Client->Server " + supportedMacCS.toString() +
				"\n");
		ret += ("Supported Mac Server->Client " + supportedMacSC.toString() +
				"\n");
		ret += ("Supported Compression Client->Server " +
				supportedCompCS.toString() + "\n");
		ret += ("Supported Compression Server->Client " +
				supportedCompSC.toString() + "\n");
		ret += ("Supported Languages Client->Server " +
				supportedLangCS.toString() + "\n");
		ret += ("Supported Languages Server->Client " +
				supportedLangSC.toString() + "\n");
		ret += ("First Kex Packet Follows [" +
				(firstKexFollows ? "TRUE]" : "FALSE]"));
		
		return ret;
	}
	
	/**
	 * @param baw
	 * @throws InvalidMessageException
	 */
	@Override
	protected void constructByteArray(ByteArrayWriter baw)
			throws InvalidMessageException {
		try {
			baw.write(cookie);
			baw.writeString(createDelimString(supportedKex));
			baw.writeString(createDelimString(supportedPK));
			baw.writeString(createDelimString(supportedEncryptCS));
			baw.writeString(createDelimString(supportedEncryptSC));
			baw.writeString(createDelimString(supportedMacCS));
			baw.writeString(createDelimString(supportedMacSC));
			baw.writeString(createDelimString(supportedCompCS));
			baw.writeString(createDelimString(supportedCompSC));
			baw.writeString(createDelimString(supportedLangCS));
			baw.writeString(createDelimString(supportedLangSC));
			baw.write((firstKexFollows ? 1 : 0));
			baw.writeInt(0);
		} catch (IOException ioe) {
			throw new InvalidMessageException("Error writing message data: " +
					ioe.getMessage());
		}
	}
	
	/**
	 * @param bar
	 * @throws InvalidMessageException
	 */
	@Override
	protected void constructMessage(ByteArrayReader bar)
			throws InvalidMessageException {
		try {
			cookie = new byte[16];
			bar.read(cookie);
			supportedKex = loadListFromString(bar.readString());
			supportedPK = loadListFromString(bar.readString());
			supportedEncryptCS = loadListFromString(bar.readString());
			supportedEncryptSC = loadListFromString(bar.readString());
			supportedMacCS = loadListFromString(bar.readString());
			supportedMacSC = loadListFromString(bar.readString());
			supportedCompCS = loadListFromString(bar.readString());
			supportedCompSC = loadListFromString(bar.readString());
			supportedLangCS = loadListFromString(bar.readString());
			supportedLangSC = loadListFromString(bar.readString());
			firstKexFollows = (bar.read() == 0) ? false : true;
		} catch (IOException ioe) {
			throw new InvalidMessageException("Error reading message data: " +
					ioe.getMessage());
		}
	}
	
	private List<String> loadListFromString(String str) {
		// Create a tokenizer object
		StringTokenizer tok = new StringTokenizer(str, ",");
		List<String> ret = new ArrayList<String>();
		
		// Iterate through the tokens adding the items to the list
		while (tok.hasMoreElements()) {
			ret.add((String) tok.nextElement());
		}
		
		return ret;
	}
	
	private List<String> sortAlgorithmList(List<String> list, String pref) {
		LinkedList<String> copy = new LinkedList<String>();
		Iterator<String> iterator = list.iterator();
		String algorithm;
		while (iterator.hasNext()) {
			algorithm = iterator.next();
			if (!algorithm.equals(pref)) {
				copy.add(algorithm);
			}
		}
		if (list.contains(pref)) {
			copy.addFirst(pref);
		}
		return copy;
	}
}
