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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link CollaborationSessionStore} that keeps the sessions in memory.
 *
 * <p>This is the default store, suitable for a single ZAP instance. The sessions are not persisted
 * and are lost when ZAP is stopped.
 */
public class InMemoryCollaborationSessionStore implements CollaborationSessionStore {

    private final Map<String, CollaborationSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void save(CollaborationSession session) {
        Objects.requireNonNull(session);
        sessions.put(session.getId(), session);
    }

    @Override
    public CollaborationSession get(String id) {
        if (id == null) {
            return null;
        }
        return sessions.get(id);
    }

    @Override
    public CollaborationSession remove(String id) {
        if (id == null) {
            return null;
        }
        return sessions.remove(id);
    }

    @Override
    public Collection<CollaborationSession> getAll() {
        return new ArrayList<>(sessions.values());
    }
}
