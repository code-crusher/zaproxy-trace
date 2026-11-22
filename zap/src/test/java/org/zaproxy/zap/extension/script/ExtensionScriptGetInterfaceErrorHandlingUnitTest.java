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
package org.zaproxy.zap.extension.script;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import javax.script.Bindings;
import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptException;
import javax.script.SimpleScriptContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.WithConfigsTest;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Unit test for the handling of errors while obtaining interfaces from scripts (issue 9297).
 *
 * <p>The GraalJS engines are automatically closed when no longer in use (graaljs add-on), if the
 * engine is closed while a class required by the script is being initialised, the errors {@code
 * NoClassDefFoundError} or {@code ExceptionInInitializerError} are thrown when obtaining the
 * interface of the script. Those errors should be reported as an error of the script, not
 * propagated to the callers, which expect no {@code Error}s (otherwise breaking the handling of
 * other scripts, for example, script scan rules falling back to generic IDs).
 */
class ExtensionScriptGetInterfaceErrorHandlingUnitTest extends WithConfigsTest {

    private ExtensionScript extensionScript;
    private ScriptWrapper script;
    private InvocableEngine engine;

    @BeforeEach
    void setUp() throws Exception {
        extensionScript = new ExtensionScript();
        extensionScript.hook(mock(org.parosproxy.paros.extension.ExtensionHook.class));
        extensionScript.getScriptParam().load(new ZapXmlConfiguration());

        engine = mock(InvocableEngine.class);
        given(engine.getContext()).willReturn(new SimpleScriptContext());

        ScriptEngineWrapper engineWrapper = mock(ScriptEngineWrapper.class);
        given(engineWrapper.getEngine()).willReturn(engine);

        script = new ScriptWrapper();
        script.setName("Test Script");
        script.setType(new ScriptType("targeted", "i18n.type", null, true));
        script.setEngine(engineWrapper);
        script.setContents("function scan() {}");
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldGetInterfaceFromEngine() throws Exception {
        // Given
        ScriptTestInterface iface = mock(ScriptTestInterface.class);
        given(engine.getInterface(ScriptTestInterface.class)).willReturn(iface);
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterface(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(sameInstance(iface)));
        assertThat(script.isError(), is(false));
    }

    @Test
    void shouldHandleExceptionThrownWhenObtainingInterface() throws Exception {
        // Given
        given(engine.getInterface(ScriptTestInterface.class))
                .willThrow(new IllegalStateException("Engine closed"));
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterface(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(nullValue()));
        assertThat(script.isError(), is(true));
        assertThat(script.isEnabled(), is(false));
    }

    @Test
    void shouldHandleNoClassDefFoundErrorThrownWhenObtainingInterface() throws Exception {
        // Given
        ScriptException cause = new ScriptException("Context closed during class init");
        given(engine.getInterface(ScriptTestInterface.class))
                .willThrow(new NoClassDefFoundErrorWithException(cause));
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterface(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(nullValue()));
        assertThat(script.isError(), is(true));
        assertThat(script.isEnabled(), is(false));
    }

    @Test
    void shouldHandleNoClassDefFoundErrorWithoutExceptionCause() throws Exception {
        // Given
        given(engine.getInterface(ScriptTestInterface.class))
                .willThrow(new NoClassDefFoundError("Could not initialize class Test"));
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterface(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(nullValue()));
        assertThat(script.isError(), is(true));
        assertThat(script.isEnabled(), is(false));
    }

    @Test
    void shouldHandleExceptionInInitializerErrorThrownWhenObtainingInterface() throws Exception {
        // Given
        given(engine.getInterface(ScriptTestInterface.class))
                .willThrow(new ExceptionInInitializerError(new ScriptException("Init failed")));
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterface(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(nullValue()));
        assertThat(script.isError(), is(true));
        assertThat(script.isEnabled(), is(false));
    }

    @Test
    void shouldHandleErrorWithoutAddOnLoader() throws Exception {
        // Given
        given(engine.getInterface(ScriptTestInterface.class))
                .willThrow(new NoClassDefFoundError("Could not initialize class Test"));
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterfaceWithOutAddOnLoader(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(nullValue()));
        assertThat(script.isError(), is(true));
        assertThat(script.isEnabled(), is(false));
    }

    @Test
    void shouldGetInterfaceWithOutAddOnLoader() throws Exception {
        // Given
        ScriptTestInterface iface = mock(ScriptTestInterface.class);
        given(engine.getInterface(ScriptTestInterface.class)).willReturn(iface);
        // When
        ScriptTestInterface obtained =
                extensionScript.getInterfaceWithOutAddOnLoader(script, ScriptTestInterface.class);
        // Then
        assertThat(obtained, is(sameInstance(iface)));
        assertThat(script.isError(), is(false));
    }

    /** A {@code NoClassDefFoundError} that carries an {@code Exception} cause. */
    private static class NoClassDefFoundErrorWithException extends NoClassDefFoundError {

        private static final long serialVersionUID = 1L;

        private final Exception cause;

        NoClassDefFoundErrorWithException(Exception cause) {
            super(cause.getMessage());
            this.cause = cause;
        }

        @Override
        public Exception getCause() {
            return cause;
        }
    }

    private interface ScriptTestInterface {}

    /**
     * A {@code ScriptEngine} that is also {@code Invocable}, for mocking the behaviour of engines
     * of scripts.
     */
    abstract static class InvocableEngine implements ScriptEngine, Invocable {

        @Override
        public abstract Object eval(String script) throws ScriptException;

        @Override
        public abstract <T> T getInterface(Class<T> clasz);

        @Override
        public ScriptEngineFactory getFactory() {
            return null;
        }

        @Override
        public ScriptContext getContext() {
            return null;
        }

        @Override
        public void setContext(ScriptContext context) {}

        @Override
        public Bindings getBindings(int scope) {
            return null;
        }

        @Override
        public void setBindings(Bindings bindings, int scope) {}

        @Override
        public Bindings createBindings() {
            return null;
        }

        @Override
        public void put(String key, Object value) {}

        @Override
        public Object get(String key) {
            return null;
        }

        @Override
        public Object invokeFunction(String name, Object... args) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object invokeMethod(Object thiz, String name, Object... args) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> T getInterface(Object thiz, Class<T> clasz) {
            throw new UnsupportedOperationException();
        }
    }
}
