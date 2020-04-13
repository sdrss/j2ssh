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
package com.sshtools.j2ssh.transport.compression;

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.io.IOUtil;
import com.sshtools.j2ssh.transport.AlgorithmNotSupportedException;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.30 $
 */
public class SshCompressionFactory {
    
    public final static String COMP_NONE = "none";
    private static String defaultAlgorithm;
    private static Map<String, Class<?>> comps;
    private static Log log = LogFactory.getLog(SshCompressionFactory.class);

    static {
        comps = new HashMap<String, Class<?>>();

        log.info("Loading compression methods");

        comps.put(COMP_NONE, null);

        defaultAlgorithm = COMP_NONE;

        try {
            Enumeration<URL> en = ConfigurationLoader.getExtensionClassLoader()
                                                  .getResources("j2ssh.compression");
            
            Properties properties = new Properties();

            while ((en != null) && en.hasMoreElements()) {
                URL url = en.nextElement();
                InputStream in = url.openStream();
                properties.load(in);
                IOUtil.closeStream(in);

                int num = 1;
                String name = "";
                Class<?> cls;

                while (properties.getProperty("compression.name." +
                            String.valueOf(num)) != null) {
                    try {
                        name = properties.getProperty("compression.name." +
                                String.valueOf(num));
                        cls = ConfigurationLoader.getExtensionClassLoader()
                                                 .loadClass(properties.getProperty(
                                    "compression.class." + String.valueOf(num)));
                        cls.newInstance();
                        comps.put(name, cls);
                        log.info("Installed " + name + " compression");
                    } catch (Throwable ex) {
                        log.info("Could not install cipher class for " + name,
                            ex);
                    }

                    num++;
                }
            }
        } catch (Throwable t) {
        }
    }

    /**
     * Creates a new SshCompressionFactory object.
     */
    protected SshCompressionFactory() {
    }

    /**
     *
     */
    public static void initialize() {
    }

    /**
     *
     *
     * @return
     */
    public static String getDefaultCompression() {
        return defaultAlgorithm;
    }

    /**
     *
     *
     * @return
     */
    public static List<String> getSupportedCompression() {
        return new ArrayList<String>(comps.keySet());
    }

    /**
     *
     *
     * @param algorithmName
     *
     * @return
     *
     * @throws AlgorithmNotSupportedException
     */
    public static SshCompression newInstance(String algorithmName)
        throws AlgorithmNotSupportedException {
        try {
            if (algorithmName.equals(COMP_NONE)) {
                return null;
            } else {
                return (SshCompression) comps.get(algorithmName).newInstance();
            }
        } catch (Exception e) {
            throw new AlgorithmNotSupportedException(algorithmName +
                " is not supported!");
        }
    }
}
