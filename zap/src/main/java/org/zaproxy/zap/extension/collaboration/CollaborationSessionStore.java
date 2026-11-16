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

import java.util.Collection;

/**
 * The storage used to keep the collaborative sessions.
 *
 * <p>The core implementation is in memory ({@link InMemoryCollaborationSessionStore}). Add-ons that
 * need to share the sessions between several ZAP instances can provide their own implementation
 * backed by a distributed cache (for example, Redis or Memcached) and register it with the {@link
 * CollaborationSessionManager}.
 */
public interface CollaborationSessionStore {

    /**
     * Stores the given session, replacing any previously stored session with the same identifier.
     *
     * @param session the session to store.
     */
    void save(CollaborationSession session);

    /**
     * Gets the session with the given identifier.
     *
     * @param id the identifier of the session.
     * @return the session, or {@code null} if not stored.
     */
    CollaborationSession get(String id);

    /**
     * Removes the session with the given identifier.
     *
     * @param id the identifier of the session.
     * @return the removed session, or {@code null} if not stored.
     */
    CollaborationSession remove(String id);

    /**
     * Gets all the stored sessions.
     *
     * @return a collection with the sessions, never {@code null}.
     */
    Collection<CollaborationSession> getAll();
}
