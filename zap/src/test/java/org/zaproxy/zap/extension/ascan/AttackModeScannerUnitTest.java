/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link AttackModeScanner}. */
class AttackModeScannerUnitTest {

    private AttackModeScanner attackModeScanner;

    @BeforeEach
    void setUp() {
        Constant.messages = mock(I18N.class);
        attackModeScanner = new AttackModeScanner(mock(ExtensionActiveScan.class));
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterConsumer(attackModeScanner);
        Constant.messages = null;
    }

    @Test
    void shouldNotBePausedByDefault() {
        assertThat(attackModeScanner.isPaused(), is(false));
    }

    @Test
    void shouldBePausedAfterPause() {
        // When
        attackModeScanner.pause();
        // Then
        assertThat(attackModeScanner.isPaused(), is(true));
    }

    @Test
    void shouldNotBePausedAfterResume() {
        // Given
        attackModeScanner.pause();
        // When
        attackModeScanner.resume();
        // Then
        assertThat(attackModeScanner.isPaused(), is(false));
    }

    @Test
    void shouldNotBePausedAfterStop() {
        // Given
        attackModeScanner.pause();
        // When
        attackModeScanner.stop();
        // Then
        assertThat(attackModeScanner.isPaused(), is(false));
    }
}
