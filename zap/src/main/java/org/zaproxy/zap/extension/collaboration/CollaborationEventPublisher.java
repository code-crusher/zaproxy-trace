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

import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.EventPublisher;

/**
 * Publishes the changes made to collaborative sessions, so that team members can be notified in
 * real time.
 */
public class CollaborationEventPublisher implements EventPublisher {

    /** A session was created. */
    public static final String SESSION_CREATED = "collaboration.session.created";

    /** A session was removed. */
    public static final String SESSION_DELETED = "collaboration.session.deleted";

    /** A member joined a session. */
    public static final String MEMBER_JOINED = "collaboration.member.joined";

    /** A member left a session. */
    public static final String MEMBER_LEFT = "collaboration.member.left";

    /** A finding was shared in a session. */
    public static final String FINDING_SHARED = "collaboration.finding.shared";

    /** A finding of a session was merged with a duplicate. */
    public static final String FINDING_MERGED = "collaboration.finding.merged";

    /** A finding of a session was updated. */
    public static final String FINDING_UPDATED = "collaboration.finding.updated";

    public static final String SESSION_ID = "sessionId";
    public static final String MEMBER = "member";
    public static final String FINDING_ID = "findingId";
    public static final String ROLE = "role";

    private static CollaborationEventPublisher publisher;

    @Override
    public String getPublisherName() {
        return CollaborationEventPublisher.class.getCanonicalName();
    }

    /**
     * Gets the publisher, registering it with the event bus if necessary.
     *
     * @return the publisher, never {@code null}.
     */
    public static synchronized CollaborationEventPublisher getPublisher() {
        if (publisher == null) {
            publisher = new CollaborationEventPublisher();
            ZAP.getEventBus()
                    .registerPublisher(
                            publisher,
                            SESSION_CREATED,
                            SESSION_DELETED,
                            MEMBER_JOINED,
                            MEMBER_LEFT,
                            FINDING_SHARED,
                            FINDING_MERGED,
                            FINDING_UPDATED);
        }
        return publisher;
    }
}
