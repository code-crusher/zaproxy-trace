/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.utils;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.net.URL;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.convert.DisabledListDelimiterHandler;
import org.apache.commons.configuration2.convert.ListDelimiterHandler;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.io.FileHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A {@code XMLConfiguration} with character encoding always set to UTF-8 and delimiter parsing
 * always disabled.
 *
 * <p><strong>Note:</strong> This class should be used, <i>always</i>, to read/write from/to the
 * configurations' file used by ZAP, this way there shouldn't be any problems with character
 * encodings.
 *
 * @see #setListDelimiterHandler(ListDelimiterHandler)
 * @see XMLConfiguration
 */
public class ZapXmlConfiguration extends XMLConfiguration {

    private static final long serialVersionUID = -8598525138011232529L;

    private static final String ENCODING = "UTF-8";

    private transient FileHandler fileHandler = new FileHandler(this);

    /** Creates a new instance of {@code ZapXmlConfiguration}. */
    public ZapXmlConfiguration() {
        super();

        fileHandler.setEncoding(ENCODING);
        super.setListDelimiterHandler(DisabledListDelimiterHandler.INSTANCE);
    }

    @Override
    public Object clone() {
        ZapXmlConfiguration copy = (ZapXmlConfiguration) super.clone();
        copy.fileHandler = new FileHandler(copy);
        copy.fileHandler.setEncoding(ENCODING);
        return copy;
    }

    /**
     * Creates a new instance of {@code ZapXmlConfiguration} with the configuration loaded from the
     * given input stream.
     *
     * @param in the input stream to load the configuration from.
     * @throws ConfigurationException if loading the configuration fails.
     * @since 2.8.0
     */
    public ZapXmlConfiguration(InputStream in) throws ConfigurationException {
        this();
        load(in);
    }

    /**
     * Creates a new instance of {@code ZapXmlConfiguration}. The configuration is loaded from the
     * file with the specified {@code fileName}.
     *
     * @param fileName the name of the file to load
     * @throws ConfigurationException if loading the configuration fails
     */
    public ZapXmlConfiguration(String fileName) throws ConfigurationException {
        this();
        setFileName(fileName);
        load();
    }

    /**
     * Creates a new instance of {@code ZapXmlConfiguration}. The configuration is loaded from the
     * specified {@code url}.
     *
     * @param url the URL
     * @throws ConfigurationException if loading the configuration fails
     */
    public ZapXmlConfiguration(URL url) throws ConfigurationException {
        this();
        setURL(url);
        load();
    }

    /**
     * Creates a new instance of {@code ZapXmlConfiguration}. The configuration is loaded from the
     * specified {@code file}.
     *
     * @param file the file that has the configuration
     * @throws ConfigurationException if loading the configuration fails
     */
    public ZapXmlConfiguration(File file) throws ConfigurationException {
        this();
        setFile(file);
        load();
    }

    @Override
    protected DocumentBuilder createDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = XmlUtils.newXxeDisabledDocumentBuilderFactory();

        // Same behaviour as base method:
        if (isValidating()) {
            factory.setValidating(true);
            if (isSchemaValidation()) {
                factory.setNamespaceAware(true);
                factory.setAttribute(
                        "http://java.sun.com/xml/jaxp/properties/schemaLanguage",
                        "http://www.w3.org/2001/XMLSchema");
            }
        }

        DocumentBuilder result = factory.newDocumentBuilder();
        result.setEntityResolver(getEntityResolver());

        if (isValidating()) {
            result.setErrorHandler(
                    new DefaultHandler() {

                        @Override
                        public void error(SAXParseException ex) throws SAXException {
                            throw ex;
                        }
                    });
        }
        return result;
    }

    @Override
    protected Transformer createTransformer() throws ConfigurationException {
        Transformer transformer = super.createTransformer();
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        return transformer;
    }

    /**
     * Calling this method has <strong>no</strong> effect. The delimiter parsing is always disabled.
     *
     * @see #setListDelimiterHandler(ListDelimiterHandler)
     */
    @Override
    public void setListDelimiterHandler(ListDelimiterHandler listDelimiterHandler) {
        // Always disabled.
    }

    /**
     * Sets the file from which the configuration is loaded and saved.
     *
     * @param file the file that has the configuration
     * @see #getFile()
     */
    public void setFile(File file) {
        fileHandler.setFile(file);
    }

    /**
     * Returns the file from which the configuration is loaded and saved, might be {@code null}.
     *
     * @return the file, or {@code null} if not set
     * @see #setFile(File)
     */
    public File getFile() {
        return fileHandler.getFile();
    }

    /**
     * Sets the name of the file from which the configuration is loaded and saved.
     *
     * @param fileName the name of the file
     * @see #getFileName()
     */
    public void setFileName(String fileName) {
        fileHandler.setFileName(fileName);
    }

    /**
     * Returns the name of the file from which the configuration is loaded and saved, might be
     * {@code null}.
     *
     * @return the name of the file, or {@code null} if not set
     * @see #setFileName(String)
     */
    public String getFileName() {
        return fileHandler.getFileName();
    }

    /**
     * Sets the URL from which the configuration is loaded and saved.
     *
     * @param url the URL
     * @see #getURL()
     */
    public void setURL(URL url) {
        fileHandler.setURL(url);
    }

    /**
     * Returns the URL from which the configuration is loaded and saved, might be {@code null}.
     *
     * @return the URL, or {@code null} if not set
     * @see #setURL(URL)
     */
    public URL getURL() {
        return fileHandler.getURL();
    }

    /**
     * Loads the configuration from the file or URL previously set.
     *
     * @throws ConfigurationException if loading the configuration fails
     */
    public void load() throws ConfigurationException {
        fileHandler.load();
    }

    /**
     * Loads the configuration from the given file.
     *
     * @param file the file that has the configuration
     * @throws ConfigurationException if loading the configuration fails
     */
    public void load(File file) throws ConfigurationException {
        fileHandler.setFile(file);
        fileHandler.load();
    }

    /**
     * Loads the configuration from the file with the given name.
     *
     * @param fileName the name of the file that has the configuration
     * @throws ConfigurationException if loading the configuration fails
     */
    public void load(String fileName) throws ConfigurationException {
        fileHandler.setFileName(fileName);
        fileHandler.load();
    }

    /**
     * Loads the configuration from the given URL.
     *
     * @param url the URL that has the configuration
     * @throws ConfigurationException if loading the configuration fails
     */
    public void load(URL url) throws ConfigurationException {
        fileHandler.setURL(url);
        fileHandler.load();
    }

    /**
     * Loads the configuration from the given input stream.
     *
     * @param in the input stream to load the configuration from
     * @throws ConfigurationException if loading the configuration fails
     */
    public void load(InputStream in) throws ConfigurationException {
        fileHandler.load(in);
    }

    /**
     * Loads the configuration from the given reader.
     *
     * @param in the reader to load the configuration from
     * @throws ConfigurationException if loading the configuration fails
     */
    public void load(Reader in) throws ConfigurationException {
        fileHandler.load(in);
    }

    /**
     * Saves the configuration to the file or URL previously set.
     *
     * @throws ConfigurationException if saving the configuration fails
     */
    public void save() throws ConfigurationException {
        fileHandler.save();
    }

    /**
     * Saves the configuration to the given file.
     *
     * @param file the file to save the configuration to
     * @throws ConfigurationException if saving the configuration fails
     */
    public void save(File file) throws ConfigurationException {
        fileHandler.save(file);
    }

    /**
     * Saves the configuration to the file with the given name.
     *
     * @param fileName the name of the file to save the configuration to
     * @throws ConfigurationException if saving the configuration fails
     */
    public void save(String fileName) throws ConfigurationException {
        fileHandler.save(fileName);
    }

    /**
     * Saves the configuration to the given URL.
     *
     * @param url the URL to save the configuration to
     * @throws ConfigurationException if saving the configuration fails
     */
    public void save(URL url) throws ConfigurationException {
        fileHandler.save(url);
    }

    /**
     * Saves the configuration to the given output stream.
     *
     * @param out the output stream to save the configuration to
     * @throws ConfigurationException if saving the configuration fails
     */
    public void save(OutputStream out) throws ConfigurationException {
        fileHandler.save(out);
    }

    /**
     * Saves the configuration to the given writer.
     *
     * @param writer the writer to save the configuration to
     * @throws ConfigurationException if saving the configuration fails
     */
    public void save(Writer writer) throws ConfigurationException {
        fileHandler.save(writer);
    }
}
