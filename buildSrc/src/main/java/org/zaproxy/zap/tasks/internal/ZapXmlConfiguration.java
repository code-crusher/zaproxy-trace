/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.tasks.internal;

import java.io.File;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.io.FileHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

public class ZapXmlConfiguration extends XMLConfiguration {

    private static final long serialVersionUID = -8598525138011232529L;

    private final transient FileHandler fileHandler = new FileHandler(this);

    public ZapXmlConfiguration() {
        super();

        fileHandler.setEncoding("UTF-8");
    }

    @Override
    protected DocumentBuilder createDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setExpandEntityReferences(false);

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

    public void load(File file) throws ConfigurationException {
        fileHandler.setFile(file);
        fileHandler.load();
    }

    public void load(InputStream in) throws ConfigurationException {
        fileHandler.load(in);
    }
}
