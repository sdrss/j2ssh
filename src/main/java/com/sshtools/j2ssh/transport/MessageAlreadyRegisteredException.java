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

import com.sshtools.j2ssh.*;


/**
 * <p>
 * Thrown by message store when a message is already registered
 * </p>
 *
 * @author Lee David Painter
 * @version $Revision: 1.19 $
 *
 * @since 0.2.0
 */
public class MessageAlreadyRegisteredException extends SshException {
    private static final long serialVersionUID = 7866354075871657375L;

    /**
     * <p>
     * Constructs the exception.
     * </p>
     *
     * @param messageId the id of the message already registered
     *
     * @since 0.2.0
     */
    public MessageAlreadyRegisteredException(Integer messageId) {
        super("Message Id " + messageId.toString() + " is already registered");
    }
}
