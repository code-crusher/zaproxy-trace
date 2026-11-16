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

/**
 * An error that occurred while operating on a collaborative session.
 *
 * <p>The {@link Kind} allows the API to map the error to the appropriate {@code ApiException} type.
 */
public class CollaborationException extends Exception {

    private static final long serialVersionUID = 1L;

    /** The kind of error. */
    public enum Kind {
        /** The session does not exist. */
        SESSION_NOT_FOUND,
        /** The member is not part of the session. */
        MEMBER_NOT_FOUND,
        /** The finding does not exist. */
        FINDING_NOT_FOUND,
        /** The member is not allowed to perform the operation. */
        NOT_ALLOWED,
        /** The provided data is not valid. */
        INVALID_DATA
    }

    private final Kind kind;

    /**
     * Constructs a {@code CollaborationException}.
     *
     * @param kind the kind of error.
     * @param message the detail message.
     */
    public CollaborationException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind getKind() {
        return kind;
    }
}
