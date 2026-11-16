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

import java.util.Objects;

/**
 * An entry of the audit trail of a collaborative session.
 *
 * <p>Every change made to a session is recorded, so that the history of an engagement can be
 * reviewed after the fact.
 */
public class AuditEntry {

    /** The kind of change recorded in the audit trail. */
    public enum Action {
        MEMBER_JOINED,
        MEMBER_LEFT,
        FINDING_SHARED,
        FINDING_MERGED,
        FINDING_UPDATED
    }

    private final long timestamp;
    private final String member;
    private final Action action;
    private final String detail;

    /**
     * Constructs an {@code AuditEntry}.
     *
     * @param timestamp the time of the change, in epoch milliseconds.
     * @param member the name of the member that made the change.
     * @param action the kind of change.
     * @param detail extra details about the change, might be empty.
     * @throws NullPointerException if {@code member} or {@code action} is {@code null}.
     */
    public AuditEntry(long timestamp, String member, Action action, String detail) {
        this.timestamp = timestamp;
        this.member = Objects.requireNonNull(member);
        this.action = Objects.requireNonNull(action);
        this.detail = detail == null ? "" : detail;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getMember() {
        return member;
    }

    public Action getAction() {
        return action;
    }

    public String getDetail() {
        return detail;
    }

    @Override
    public String toString() {
        return "AuditEntry [timestamp="
                + timestamp
                + ", member="
                + member
                + ", action="
                + action
                + ", detail="
                + detail
                + "]";
    }
}
