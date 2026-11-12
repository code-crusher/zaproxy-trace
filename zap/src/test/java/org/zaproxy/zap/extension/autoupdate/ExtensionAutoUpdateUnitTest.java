/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.autoupdate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.io.StringReader;
import java.net.URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.AddOnCollection;
import org.zaproxy.zap.control.AddOnCollection.Platform;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionAutoUpdate}. */
class ExtensionAutoUpdateUnitTest {

    private static final String CONF =
            "<ZAP>\n"
                    + "	<addon>levoai</addon>\n"
                    + "	<addon_levoai>\n"
                    + "		<name>Levo.ai</name>\n"
                    + "		<version>0.3.0</version>\n"
                    + "		<file>levoai-zap-addon-alpha-0.3.0.zap</file>\n"
                    + "		<status>alpha</status>\n"
                    + "		<url>https://example.com/levoai-zap-addon-alpha-0.3.0.zap</url>\n"
                    + "		<size>1234</size>\n"
                    + "	</addon_levoai>\n"
                    + "</ZAP>";

    private AddOnCollection addOns;

    @BeforeEach
    void setUp() throws Exception {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setDelimiterParsingDisabled(true);
        config.load(new StringReader(CONF));
        addOns = new AddOnCollection(config, Platform.daily);
    }

    @Test
    void shouldGetAddOnByUrl() throws Exception {
        // Given
        URL url = new URL("https://example.com/levoai-zap-addon-alpha-0.3.0.zap");
        // When
        AddOn addOn = ExtensionAutoUpdate.getAddOnByUrl(addOns, url);
        // Then
        assertThat(addOn, is(equalTo(addOns.getAddOn("levoai"))));
    }

    @Test
    void shouldNotGetAddOnByUrlIfNotMatching() throws Exception {
        // Given
        URL url = new URL("https://example.com/other-alpha-1.0.0.zap");
        // When
        AddOn addOn = ExtensionAutoUpdate.getAddOnByUrl(addOns, url);
        // Then
        assertThat(addOn, is(nullValue()));
    }

    @Test
    void shouldNotGetAddOnByUrlIfCollectionIsNull() throws Exception {
        // Given
        URL url = new URL("https://example.com/levoai-zap-addon-alpha-0.3.0.zap");
        // When
        AddOn addOn = ExtensionAutoUpdate.getAddOnByUrl(null, url);
        // Then
        assertThat(addOn, is(nullValue()));
    }

    @Test
    void shouldNotGetAddOnByUrlIfUrlIsNull() {
        // When
        AddOn addOn = ExtensionAutoUpdate.getAddOnByUrl(addOns, null);
        // Then
        assertThat(addOn, is(nullValue()));
    }
}
