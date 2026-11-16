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
package org.zaproxy.zap.extension.collaboration;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/**
 * The extension that provides collaborative scan sessions, allowing a team to share the findings of
 * an engagement in real time.
 */
public class ExtensionCollaboration extends ExtensionAdaptor {

    public static final String NAME = "ExtensionCollaboration";

    private CollaborationSessionManager sessionManager;

    public ExtensionCollaboration() {
        super(NAME);
        this.setOrder(311);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("collaboration.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("collaboration.desc");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addApiImplementor(new CollaborationAPI(getSessionManager()));
    }

    /**
     * Gets the manager of the collaborative sessions.
     *
     * @return the session manager, never {@code null}.
     */
    public CollaborationSessionManager getSessionManager() {
        if (sessionManager == null) {
            sessionManager = new CollaborationSessionManager();
        }
        return sessionManager;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public boolean isCore() {
        return true;
    }
}
