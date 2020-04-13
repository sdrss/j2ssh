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
package com.sshtools.j2ssh.agent;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.transport.publickey.InvalidSshKeyException;
import com.sshtools.j2ssh.transport.publickey.InvalidSshKeySignatureException;
import com.sshtools.j2ssh.transport.publickey.SshPrivateKey;
import com.sshtools.j2ssh.transport.publickey.SshPublicKey;

/**
 *
 *
 * @author $author$
 * @version $Revision: 1.14 $
 */
public class KeyStore {
    @SuppressWarnings("unused")
    private static Log log = LogFactory.getLog(KeyStore.class);
    HashMap<SshPublicKey, String> publickeys = new HashMap<SshPublicKey, String>();
    Map<SshPublicKey, SshPrivateKey> privatekeys = new HashMap<SshPublicKey, SshPrivateKey>();
    Map<SshPublicKey, KeyConstraints> constraints = new HashMap<SshPublicKey, KeyConstraints>();
    Vector<SshPublicKey> index = new Vector<SshPublicKey>();
    Vector<KeyStoreListener> listeners = new Vector<KeyStoreListener>();
    String lockedPassword = null;

    /**
     * Creates a new KeyStore object.
     */
    public KeyStore() {
    }

    /**
     *
     *
     * @return
     */
    public Map<SshPublicKey, String> getPublicKeys() {
	//return (Map<SshPublicKey, String>) publickeys.clone();
	return new HashMap<SshPublicKey, String>(publickeys);
    }

    /**
     *
     *
     * @param key
     *
     * @return
     */
    public int indexOf(SshPublicKey key) {
	return index.indexOf(key);
    }

    /**
     *
     *
     * @param i
     *
     * @return
     */
    public SshPublicKey elementAt(int i) {
	return (SshPublicKey) index.elementAt(i);
    }

    /**
     *
     *
     * @param key
     *
     * @return
     */
    public String getDescription(SshPublicKey key) {
	return (String) publickeys.get(key);
    }

    /**
     *
     *
     * @param key
     *
     * @return
     */
    public KeyConstraints getKeyConstraints(SshPublicKey key) {
	return (KeyConstraints) constraints.get(key);
    }

    /**
     *
     *
     * @return
     */
    public int size() {
	return index.size();
    }

    /**
     *
     *
     * @param listener
     */
    public void addKeyStoreListener(KeyStoreListener listener) {
	listeners.add(listener);
    }

    /**
     *
     *
     * @param listener
     */
    public void removeKeyStoreListener(KeyStoreListener listener) {
	listeners.remove(listener);
    }

    /**
     *
     *
     * @param prvkey
     * @param pubkey
     * @param description
     * @param cs
     *
     * @return
     *
     * @throws IOException
     */
    public boolean addKey(SshPrivateKey prvkey, SshPublicKey pubkey,
	    String description, KeyConstraints cs) throws IOException {
	synchronized (publickeys) {
	    if (!publickeys.containsKey(pubkey)) {
		publickeys.put(pubkey, description);
		privatekeys.put(pubkey, prvkey);
		constraints.put(pubkey, cs);
		index.add(pubkey);

		for (KeyStoreListener listener : listeners) {
		    listener.onAddKey(this);
		}

		return true;
	    } else {
		return false;
	    }
	}
    }

    /**
     *
     */
    public void deleteAllKeys() {
	synchronized (publickeys) {
	    publickeys.clear();
	    privatekeys.clear();
	    constraints.clear();
	    index.clear();

	    for (KeyStoreListener listener : listeners) {
		listener.onDeleteAllKeys(this);
	    }
	}
    }

    /**
     *
     *
     * @param pubkey
     * @param forwardingNodes
     * @param data
     *
     * @return
     *
     * @throws KeyTimeoutException
     * @throws InvalidSshKeyException
     * @throws InvalidSshKeySignatureException
     */
    public byte[] performHashAndSign(SshPublicKey pubkey,
	    List<ForwardingNotice> forwardingNodes, byte[] data)
	    throws KeyTimeoutException, InvalidSshKeyException,
	    InvalidSshKeySignatureException {
	synchronized (publickeys) {
	    if (privatekeys.containsKey(pubkey)) {
		SshPrivateKey key = privatekeys.get(pubkey);
		KeyConstraints cs = constraints.get(pubkey);

		if (cs.canUse()) {
		    if (!cs.hasTimedOut()) {
			cs.use();

			byte[] sig = key.generateSignature(data);

			for (KeyStoreListener listener : listeners) {
			    listener.onKeyOperation(this, "hash-and-sign");
			}

			return sig;
		    } else {
			throw new KeyTimeoutException();
		    }
		} else {
		    throw new KeyTimeoutException();
		}
	    } else {
		throw new InvalidSshKeyException("The key does not exist");
	    }
	}
    }

    /**
     *
     *
     * @param pubkey
     * @param description
     *
     * @return
     *
     * @throws IOException
     */
    public boolean deleteKey(SshPublicKey pubkey, String description)
	    throws IOException {
	synchronized (publickeys) {
	    if (publickeys.containsKey(pubkey)) {
		String desc = (String) publickeys.get(pubkey);

		if (description.equals(desc)) {
		    publickeys.remove(pubkey);
		    privatekeys.remove(pubkey);
		    constraints.remove(pubkey);
		    index.remove(pubkey);

		    for (KeyStoreListener listener : listeners) {
			listener.onDeleteKey(this);
		    }

		    return true;
		}
	    }

	    return false;
	}
    }

    /**
     *
     *
     * @param password
     *
     * @return
     *
     * @throws IOException
     */
    public boolean lock(String password) throws IOException {
	synchronized (publickeys) {
	    if (lockedPassword == null) {
		lockedPassword = password;

		for (KeyStoreListener listener : listeners) {
		    listener.onLock(this);
		}

		return true;
	    } else {
		return false;
	    }
	}
    }

    /**
     *
     *
     * @param password
     *
     * @return
     *
     * @throws IOException
     */
    public boolean unlock(String password) throws IOException {
	synchronized (publickeys) {
	    if (lockedPassword != null) {
		if (password.equals(lockedPassword)) {
		    lockedPassword = null;

		    for (KeyStoreListener listener : listeners) {
			listener.onUnlock(this);
		    }

		    return true;
		}
	    }

	    return false;
	}
    }
}
