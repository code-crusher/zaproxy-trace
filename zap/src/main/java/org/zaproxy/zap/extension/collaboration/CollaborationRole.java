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

import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/**
 * The role of a member of a collaborative session.
 *
 * <p>Each role grants a fixed set of {@link Permission permissions}, so that a team can split the
 * work of an engagement between the testers running scans, the reviewers triaging the findings and
 * the people producing the final report.
 */
public enum CollaborationRole {

    /** Runs scans and shares the findings. */
    SCANNER(Permission.SHARE_FINDINGS),

    /** Runs scans, shares findings and triages them (for example, marking false positives). */
    REVIEWER(Permission.SHARE_FINDINGS, Permission.UPDATE_FINDINGS),

    /** Views the findings and exports the consolidated report. */
    REPORTER(Permission.EXPORT_REPORTS);

    /** An operation that a role may or may not be allowed to perform. */
    public enum Permission {
        SHARE_FINDINGS,
        UPDATE_FINDINGS,
        EXPORT_REPORTS
    }

    private final Set<Permission> permissions;

    CollaborationRole(Permission first, Permission... others) {
        Set<Permission> granted = EnumSet.of(first, others);
        this.permissions = Collections.unmodifiableSet(granted);
    }

    /**
     * Gets the permissions granted to this role.
     *
     * @return an unmodifiable set with the permissions, never {@code null}.
     */
    public Set<Permission> getPermissions() {
        return permissions;
    }

    /**
     * Tells whether or not this role grants the given permission.
     *
     * @param permission the permission to check.
     * @return {@code true} if granted, {@code false} otherwise.
     */
    public boolean has(Permission permission) {
        return permissions.contains(permission);
    }

    /**
     * Gets the role with the given name, ignoring case.
     *
     * @param name the name of the role.
     * @return the role, or {@code null} if there is no role with the given name.
     */
    public static CollaborationRole fromName(String name) {
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
