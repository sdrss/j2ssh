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
package com.sshtools.daemon.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.sshtools.j2ssh.configuration.ExtensionAlgorithm;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.12 $
 */
public class SshAPIConfiguration extends DefaultHandler
    implements com.sshtools.j2ssh.configuration.SshAPIConfiguration {
    private String defaultCipher = null;
    private String defaultMac = null;
    private String defaultCompression = null;
    private String defaultPublicKey = null;
    private String defaultKeyExchange = null;
    private List<ExtensionAlgorithm> cipherExtensions = new ArrayList<ExtensionAlgorithm>();
    private List<ExtensionAlgorithm> macExtensions = new ArrayList<ExtensionAlgorithm>();
    private List<ExtensionAlgorithm> compressionExtensions = new ArrayList<ExtensionAlgorithm>();
    private List<ExtensionAlgorithm> pkExtensions = new ArrayList<ExtensionAlgorithm>();
    private List<ExtensionAlgorithm> kexExtensions = new ArrayList<ExtensionAlgorithm>();
    private List<ExtensionAlgorithm> authExtensions = new ArrayList<ExtensionAlgorithm>();
    private List<String> pkFormats = new ArrayList<String>();
    private List<String> prvFormats = new ArrayList<String>();
    private String defaultPublicFormat = null;
    private String defaultPrivateFormat = null;
    private String currentElement = null;
    private String parentElement = null;
    //private List currentList = null;
    private ExtensionAlgorithm currentExt = null;

    /**
 * Creates a new SshAPIConfiguration object.
 *
 * @param in
 *
 * @throws SAXException
 * @throws ParserConfigurationException
 * @throws IOException
 */
    public SshAPIConfiguration(InputStream in)
        throws SAXException, ParserConfigurationException, IOException {
        reload(in);
    }

    /**
 *
 *
 * @param in
 *
 * @throws SAXException
 * @throws ParserConfigurationException
 * @throws IOException
 */
    public void reload(InputStream in)
        throws SAXException, ParserConfigurationException, IOException {
        defaultCipher = null;
        defaultMac = null;
        defaultCompression = null;
        defaultKeyExchange = null;
        defaultPublicKey = null;
        defaultPublicFormat = null;
        defaultPrivateFormat = null;
        cipherExtensions.clear();
        macExtensions.clear();
        compressionExtensions.clear();
        pkExtensions.clear();
        kexExtensions.clear();
        authExtensions.clear();
        pkFormats.clear();
        prvFormats.clear();

        SAXParserFactory saxFactory = SAXParserFactory.newInstance();
        SAXParser saxParser = saxFactory.newSAXParser();
        saxParser.parse(in, this);
    }

    /**
 *
 *
 * @param ch
 * @param start
 * @param length
 *
 * @throws SAXException
 */
    public void characters(char[] ch, int start, int length)
        throws SAXException {
        String value = new String(ch, start, length);

        if (currentElement != null) {
            if (currentElement.equals("AlgorithmName")) {
                if (currentExt != null) {
                    currentExt.setAlgorithmName(value);
                } else {
                    throw new SAXException("Unexpected AlgorithmName element!");
                }

                return;
            }

            if (currentElement.equals("ImplementationClass")) {
                if (currentExt != null) {
                    currentExt.setImplementationClass(value);
                } else {
                    throw new SAXException(
                        "Unexpected ImplementationClass element!");
                }

                return;
            }

            if (currentElement.equals("DefaultAlgorithm")) {
                if (parentElement.equals("CipherConfiguration")) {
                    defaultCipher = value;
                } else if (parentElement.equals("MacConfiguration")) {
                    defaultMac = value;
                } else if (parentElement.equals("CompressionConfiguration")) {
                    defaultCompression = value;
                } else if (parentElement.equals("PublicKeyConfiguration")) {
                    defaultPublicKey = value;
                } else if (parentElement.equals("KeyExchangeConfiguration")) {
                    defaultKeyExchange = value;
                } else {
                    throw new SAXException(
                        "Unexpected parent elemenet for DefaultAlgorithm element");
                }
            }

            if (currentElement.equals("DefaultPublicFormat")) {
                defaultPublicFormat = value;
            }

            if (currentElement.equals("DefaultPrivateFormat")) {
                defaultPrivateFormat = value;
            }
        }
    }

    /**
 *
 *
 * @param uri
 * @param localName
 * @param qname
 *
 * @throws SAXException
 */
    public void endElement(String uri, String localName, String qname)
        throws SAXException {
        if (currentElement != null) {
            if (!currentElement.equals(qname)) {
                throw new SAXException("Unexpected end element found " + qname);
            } else if (currentElement.equals("SshAPIConfiguration")) {
                currentElement = null;
            } else if (currentElement.equals("CipherConfiguration") ||
                    currentElement.equals("MacConfiguration") ||
                    currentElement.equals("PublicKeyConfiguration") ||
                    currentElement.equals("CompressionConfiguration") ||
                    currentElement.equals("KeyExchangeConfiguration") ||
                    currentElement.equals("AuthenticationConfiguration")) {
                //currentList = null;
                currentElement = "SshAPIConfiguration";
            } else if (currentElement.equals("ExtensionAlgorithm")) {
                if (currentExt == null) {
                    throw new SAXException(
                        "Critical error, null extension algortihm");
                }

                if ((currentExt.getAlgorithmName() == null) ||
                        (currentExt.getImplementationClass() == null)) {
                    throw new SAXException(
                        "Unexpected end of ExtensionAlgorithm Element");
                }

                //currentList.add(currentExt);
                currentExt = null;
                currentElement = parentElement;
            } else if (currentElement.equals("DefaultAlgorithm") ||
                    currentElement.equals("DefaultPublicFormat") ||
                    currentElement.equals("DefaultPrivateFormat") ||
                    currentElement.equals("PublicKeyFormat") ||
                    currentElement.equals("PrivateKeyFormat")) {
                currentElement = parentElement;
            } else if (currentElement.equals("AlgorithmName")) {
                currentElement = "ExtensionAlgorithm";
            } else if (currentElement.equals("ImplementationClass")) {
                currentElement = "ExtensionAlgorithm";
            } else {
                throw new SAXException("Unexpected end element " + qname);
            }
        }
    }

    /**
 *
 *
 * @param uri
 * @param localName
 * @param qname
 * @param attrs
 *
 * @throws SAXException
 */
    public void startElement(String uri, String localName, String qname,
        Attributes attrs) throws SAXException {
        if (currentElement == null) {
            if (!qname.equals("SshAPIConfiguration")) {
                throw new SAXException("Unexpected root element " + qname);
            }
        } else {
            if (currentElement.equals("SshAPIConfiguration")) {
                if (!qname.equals("CipherConfiguration") &&
                        !qname.equals("MacConfiguration") &&
                        !qname.equals("CompressionConfiguration") &&
                        !qname.equals("PublicKeyConfiguration") &&
                        !qname.equals("AuthenticationConfiguration") &&
                        !qname.equals("KeyExchangeConfiguration")) {
                    throw new SAXException("Unexpected <" + qname +
                        "> element after SshAPIConfiguration");
                }
            } else if (currentElement.equals("CipherConfiguration")) {
                if (qname.equals("ExtensionAlgorithm")) {
                    //currentList = cipherExtensions;
                    parentElement = currentElement;
                    currentExt = new ExtensionAlgorithm();
                } else if (qname.equals("DefaultAlgorithm")) {
                    parentElement = currentElement;
                } else {
                    throw new SAXException("Unexpected element <" + qname +
                        "> found after CipherConfiguration");
                }
            } else if (currentElement.equals("MacConfiguration")) {
                if (qname.equals("ExtensionAlgorithm")) {
                    //currentList = macExtensions;
                    parentElement = currentElement;
                    currentExt = new ExtensionAlgorithm();
                } else if (qname.equals("DefaultAlgorithm")) {
                    parentElement = currentElement;
                } else {
                    throw new SAXException("Unexpected element <" + qname +
                        "> found after CipherConfiguration");
                }
            } else if (currentElement.equals("CompressionConfiguration")) {
                if (qname.equals("ExtensionAlgorithm")) {
                    //currentList = compressionExtensions;
                    parentElement = currentElement;
                    currentExt = new ExtensionAlgorithm();
                } else if (qname.equals("DefaultAlgorithm")) {
                    parentElement = currentElement;
                } else {
                    throw new SAXException("Unexpected element <" + qname +
                        "> found after CompressionConfiguration");
                }
            } else if (currentElement.equals("PublicKeyConfiguration")) {
                if (qname.equals("ExtensionAlgorithm")) {
                    //currentList = pkExtensions;
                    parentElement = currentElement;
                    currentExt = new ExtensionAlgorithm();
                } else if (qname.equals("DefaultAlgorithm")) {
                    parentElement = currentElement;
                } else if (qname.equals("PublicKeyFormat")) {
                    String cls = attrs.getValue("ImplementationClass");

                    if (cls == null) {
                        throw new SAXException(
                            "<PublicKeyFormat> element requries the ImplementationClass attribute");
                    }

                    pkFormats.add(cls);
                } else if (qname.equals("PrivateKeyFormat")) {
                    String cls = attrs.getValue("ImplementationClass");

                    if (cls == null) {
                        throw new SAXException(
                            "<PrivateKeyFormat> element requries the ImplementationClass attribute");
                    }

                    prvFormats.add(cls);
                } else if (qname.equals("DefaultPublicFormat")) {
                    parentElement = currentElement;
                } else if (qname.equals("DefaultPrivateFormat")) {
                    parentElement = currentElement;
                } else {
                    throw new SAXException("Unexpected element <" + qname +
                        "> found after PublicKeyConfiguration");
                }
            } else if (currentElement.equals("AuthenticationConfiguration")) {
                if (qname.equals("ExtensionAlgorithm")) {
                    //currentList = authExtensions;
                    parentElement = currentElement;
                    currentExt = new ExtensionAlgorithm();
                } else {
                    throw new SAXException("Unexpected element <" + qname +
                        "> found after AuthenticationConfiguration");
                }
            } else if (currentElement.equals("KeyExchangeConfiguration")) {
                if (qname.equals("ExtensionAlgorithm")) {
                    //currentList = kexExtensions;
                    parentElement = currentElement;
                    currentExt = new ExtensionAlgorithm();
                } else if (qname.equals("DefaultAlgorithm")) {
                    parentElement = currentElement;
                } else {
                    throw new SAXException("Unexpected element <" + qname +
                        "> found after KeyExchangeConfiguration");
                }
            } else if ((currentElement.equals("ExtensionAlgorithm") &&
                    qname.equals("AlgorithmName")) ||
                    (currentElement.equals("ExtensionAlgorithm") &&
                    qname.equals("ImplementationClass"))) {
            } else {
                throw new SAXException("Unexpected element " + qname);
            }
        }

        currentElement = qname;
    }

    /**
 *
 *
 * @return
 */
    public List<ExtensionAlgorithm> getCompressionExtensions() {
        return compressionExtensions;
    }

    /**
 *
 *
 * @return
 */
    public List<ExtensionAlgorithm> getCipherExtensions() {
        return cipherExtensions;
    }

    /**
 *
 *
 * @return
 */
    public List<ExtensionAlgorithm> getMacExtensions() {
        return macExtensions;
    }

    /**
 *
 *
 * @return
 */
    public List<ExtensionAlgorithm> getAuthenticationExtensions() {
        return authExtensions;
    }

    /**
 *
 *
 * @return
 */
    public List<ExtensionAlgorithm> getPublicKeyExtensions() {
        return pkExtensions;
    }

    /**
 *
 *
 * @return
 */
    public List<ExtensionAlgorithm> getKeyExchangeExtensions() {
        return kexExtensions;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultCipher() {
        return defaultCipher;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultMac() {
        return defaultMac;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultCompression() {
        return defaultCompression;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultPublicKey() {
        return defaultPublicKey;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultKeyExchange() {
        return defaultKeyExchange;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultPublicKeyFormat() {
        return defaultPublicFormat;
    }

    /**
 *
 *
 * @return
 */
    public String getDefaultPrivateKeyFormat() {
        return defaultPrivateFormat;
    }

    /**
 *
 *
 * @return
 */
    public List<String> getPublicKeyFormats() {
        return pkFormats;
    }

    /**
 *
 *
 * @return
 */
    public List<String> getPrivateKeyFormats() {
        return prvFormats;
    }

    /**
 *
 *
 * @return
 */
    public String toString() {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        xml += "<!-- Sshtools J2SSH Configuration file -->\n";
        xml += "<SshAPIConfiguration>\n";
        xml += "   <!-- The Cipher configuration, add or overide default cipher implementations -->\n";
        xml += "   <CipherConfiguration>\n";

        
        for(final ExtensionAlgorithm ext : cipherExtensions) {
            xml += "      <ExtensionAlgorithm>\n";
            xml += ("         <AlgorithmName>" + ext.getAlgorithmName() +
            "</AlgorithmName>\n");
            xml += ("         <ImplementationClass>" +
            ext.getImplementationClass() + "</ImplementationClass>\n");
            xml += "      </ExtensionAlgorithm>\n";
        }

        xml += ("      <DefaultAlgorithm>" + defaultCipher +
        "</DefaultAlgorithm>\n");
        xml += "   </CipherConfiguration>\n";
        xml += "   <!-- The Mac configuration, add or overide default mac implementations -->\n";
        xml += "   <MacConfiguration>\n";

        for(final ExtensionAlgorithm ext : macExtensions ) {   
            xml += "      <ExtensionAlgorithm>\n";
            xml += ("         <AlgorithmName>" + ext.getAlgorithmName() +
            "</AlgorithmName>\n");
            xml += ("         <ImplementationClass>" +
            ext.getImplementationClass() + "</ImplementationClass>\n");
            xml += "      </ExtensionAlgorithm>\n";
        }

        xml += ("      <DefaultAlgorithm>" + defaultMac +
        "</DefaultAlgorithm>\n");
        xml += "   </MacConfiguration>\n";
        xml += "   <!-- The Compression configuration, add or overide default compression implementations -->\n";
        xml += "   <CompressionConfiguration>\n";
        

        for(final ExtensionAlgorithm ext : compressionExtensions ) {   
            xml += "      <ExtensionAlgorithm>\n";
            xml += ("         <AlgorithmName>" + ext.getAlgorithmName() +
            "</AlgorithmName>\n");
            xml += ("         <ImplementationClass>" +
            ext.getImplementationClass() + "</ImplementationClass>\n");
            xml += "      </ExtensionAlgorithm>\n";
        }

        xml += ("      <DefaultAlgorithm>" + defaultCompression +
        "</DefaultAlgorithm>\n");
        xml += "   </CompressionConfiguration>\n";
        xml += "   <!-- The Public Key configuration, add or overide default public key implementations -->\n";
        xml += "   <PublicKeyConfiguration>\n";

        for(final ExtensionAlgorithm ext : pkExtensions ) {   
            xml += "      <ExtensionAlgorithm>\n";
            xml += ("         <AlgorithmName>" + ext.getAlgorithmName() +
            "</AlgorithmName>\n");
            xml += ("         <ImplementationClass>" +
            ext.getImplementationClass() + "</ImplementationClass>\n");
            xml += "      </ExtensionAlgorithm>\n";
        }

        xml += ("      <DefaultAlgorithm>" + defaultPublicKey +
        "</DefaultAlgorithm>\n");
        
        for(final String cls : pkFormats) {
            xml += ("      <PublicKeyFormat ImplementationClass=\"" + cls +
            "\"/>\n");
        }

        for(final String cls : prvFormats) {
            xml += ("      <PrivateKeyFormat ImplementationClass=\"" + cls +
            "\"/>\n");
        }

        xml += ("      <DefaultPublicFormat>" + defaultPublicFormat +
        "</DefaultPublicFormat>\n");
        xml += ("      <DefaultPrivateFormat>" + defaultPrivateFormat +
        "</DefaultPrivateFormat>\n");
        xml += "   </PublicKeyConfiguration>\n";
        xml += "   <!-- The Key Exchange configuration, add or overide default key exchange implementations -->\n";
        xml += "   <KeyExchangeConfiguration>\n";

        for(final ExtensionAlgorithm ext : kexExtensions ) {   
            xml += "      <ExtensionAlgorithm>\n";
            xml += ("         <AlgorithmName>" + ext.getAlgorithmName() +
            "</AlgorithmName>\n");
            xml += ("         <ImplementationClass>" +
            ext.getImplementationClass() + "</ImplementationClass>\n");
            xml += "      </ExtensionAlgorithm>\n";
        }

        xml += ("      <DefaultAlgorithm>" + defaultKeyExchange +
        "</DefaultAlgorithm>\n");
        xml += "   </KeyExchangeConfiguration>\n";
        xml += "   <!-- The Authentication configuration, add or overide default authentication implementations -->\n";
        xml += "   <AuthenticationConfiguration>\n";

        for(final ExtensionAlgorithm ext : authExtensions ) {   
            xml += "      <ExtensionAlgorithm>\n";
            xml += ("         <AlgorithmName>" + ext.getAlgorithmName() +
            "</AlgorithmName>\n");
            xml += ("         <ImplementationClass>" +
            ext.getImplementationClass() + "</ImplementationClass>\n");
            xml += "      </ExtensionAlgorithm>\n";
        }

        xml += "   </AuthenticationConfiguration>\n";
        xml += "</SshAPIConfiguration>";

        return xml;
    }
}
