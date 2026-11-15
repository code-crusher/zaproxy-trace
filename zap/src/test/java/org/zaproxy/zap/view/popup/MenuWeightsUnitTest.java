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
package org.zaproxy.zap.view.popup;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/** Unit test for the {@code AI Assisted} popup menu shared by the AI add-ons. */
class MenuWeightsUnitTest {

    /**
     * Key in the core {@code Messages.properties} for the text of the "AI Assisted" super menu.
     * Add-ons showing AI features under the same super menu are expected to use the same key, so
     * the items are grouped under a single menu item and not scattered over multiple ones.
     */
    static final String AI_ASSISTED_POPUP_KEY = "ai.assisted.popup";

    @Test
    void shouldHaveAiAssistedWeight() {
        assertThat(MenuWeights.MENU_AI_ASSISTED_WEIGHT, is(equalTo(29000)));
    }

    @Test
    void shouldHaveAiAssistedPopupMessage() {
        Properties messages = loadCoreMessages();

        assertThat(messages.getProperty(AI_ASSISTED_POPUP_KEY), is(notNullValue()));
        assertThat(messages.getProperty(AI_ASSISTED_POPUP_KEY), is(equalTo("AI Assisted")));
    }

    private static Properties loadCoreMessages() {
        Properties props = new Properties();
        try (InputStream in =
                MenuWeightsUnitTest.class.getResourceAsStream(
                        "/org/zaproxy/zap/resources/Messages.properties")) {
            if (in == null) {
                throw new IllegalStateException("Messages.properties not found on the classpath");
            }
            props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return props;
    }
}
