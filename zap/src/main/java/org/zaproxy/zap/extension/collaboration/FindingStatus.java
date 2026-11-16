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

import java.util.Locale;

/** The triage status of a finding shared in a collaborative session. */
public enum FindingStatus {

    /** The finding was shared but not yet reviewed. */
    OPEN,

    /** The finding was reviewed and confirmed. */
    CONFIRMED,

    /** The finding was reviewed and considered a false positive. */
    FALSE_POSITIVE;

    /**
     * Gets the status with the given name, ignoring case.
     *
     * @param name the name of the status.
     * @return the status, or {@code null} if there is no status with the given name.
     */
    public static FindingStatus fromName(String name) {
        if (name == null) {
            return null;
        }
        try {
            return valueOf(name.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
