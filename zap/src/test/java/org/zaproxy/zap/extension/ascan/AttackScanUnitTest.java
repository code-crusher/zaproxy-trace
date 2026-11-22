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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.zaproxy.zap.extension.ascan.AttackModeScanner.AttackModeScannerThread;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link AttackScan}. */
class AttackScanUnitTest {

    private AttackModeScannerThread attackModeScannerThread;
    private AttackScan attackScan;

    @BeforeAll
    static void beforeAll() {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @AfterAll
    static void afterAll() {
        Constant.messages = null;
    }

    @BeforeEach
    void setUp() {
        Control.initSingletonForTesting();
        attackModeScannerThread = mock(AttackModeScannerThread.class);
        attackScan =
                new AttackScan(
                        "Attack Mode Scanner",
                        mock(ScannerParam.class),
                        mock(ScanPolicy.class),
                        null,
                        attackModeScannerThread);
    }

    @Test
    void shouldNotBePausedByDefault() {
        // Given
        given(attackModeScannerThread.isPaused()).willReturn(false);
        // When / Then
        assertThat(attackScan.isPaused(), is(false));
    }

    @Test
    void shouldPauseAttackModeScannerThread() {
        // When
        attackScan.pauseScan();
        // Then
        verify(attackModeScannerThread).pause();
    }

    @Test
    void shouldResumeAttackModeScannerThread() {
        // When
        attackScan.resumeScan();
        // Then
        verify(attackModeScannerThread).resume();
    }

    @Test
    void shouldReturnPausedStateOfAttackModeScannerThread() {
        // Given
        given(attackModeScannerThread.isPaused()).willReturn(true);
        // When / Then
        assertThat(attackScan.isPaused(), is(true));
    }

    @Test
    void shouldNotFailToPauseWithoutAttackModeScannerThread() {
        // Given
        attackScan =
                new AttackScan(
                        "Attack Mode Scanner",
                        mock(ScannerParam.class),
                        mock(ScanPolicy.class),
                        null,
                        null);
        // When
        attackScan.pauseScan();
        attackScan.resumeScan();
        // Then
        assertThat(attackScan.isPaused(), is(false));
        verifyNoInteractions(attackModeScannerThread);
    }
}
