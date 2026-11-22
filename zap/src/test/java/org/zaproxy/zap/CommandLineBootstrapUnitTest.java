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
package org.zaproxy.zap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;

/** Unit test for {@link CommandLineBootstrap}. */
class CommandLineBootstrapUnitTest extends WithConfigsTest {

    private Control control;
    private List<String> events;
    private TestCommandLineBootstrap bootstrap;

    @BeforeEach
    void setUp() throws Exception {
        // The low memory option can be set only once per JVM, reset it to allow starting again.
        Field lowMemoryOption = Constant.class.getDeclaredField("lowMemoryOption");
        lowMemoryOption.setAccessible(true);
        lowMemoryOption.set(null, null);

        events = new ArrayList<>();
        control = mock(Control.class);
        given(control.getExtensionLoader()).willReturn(mock(ExtensionLoader.class));
        willAnswer(
                        invocation -> {
                            events.add("shutdown");
                            return null;
                        })
                .given(control)
                .shutdown(anyBoolean());
        bootstrap =
                new TestCommandLineBootstrap(
                        new CommandLine(new String[] {CommandLine.CMD, CommandLine.NOSTDOUT}),
                        control,
                        events);
    }

    @Test
    void shouldExitWithControlStatusAfterShutdown() throws Exception {
        // Given
        given(control.getExitStatus()).willReturn(3);
        // When
        int status = bootstrap.start();
        // Then
        assertThat(status, is(equalTo(3)));
        assertThat(bootstrap.getExitStatus(), is(equalTo(3)));
        assertThat(events, contains("shutdown", "exit"));
        verify(control).runCommandLine();
    }

    @Test
    void shouldExitWithOneIfShutdownRequested() throws Exception {
        // Given
        willThrow(new ShutdownRequestedException()).given(control).runCommandLine();
        // When
        int status = bootstrap.start();
        // Then
        assertThat(status, is(equalTo(1)));
        assertThat(bootstrap.getExitStatus(), is(equalTo(1)));
        assertThat(events, contains("shutdown", "exit"));
    }

    private static class TestCommandLineBootstrap extends CommandLineBootstrap {

        private final Control control;
        private final List<String> events;
        private int exitStatus;

        TestCommandLineBootstrap(CommandLine args, Control control, List<String> events) {
            super(args);
            this.control = control;
            this.events = events;
        }

        @Override
        protected Control initControl() {
            return control;
        }

        @Override
        protected void initModel() {
            // Nothing to do.
        }

        @Override
        protected void warnAddOnsAndExtensionsNoLongerRunnable() {
            // Nothing to do.
        }

        @Override
        void exit(int status) {
            events.add("exit");
            exitStatus = status;
        }

        int getExitStatus() {
            return exitStatus;
        }
    }
}
