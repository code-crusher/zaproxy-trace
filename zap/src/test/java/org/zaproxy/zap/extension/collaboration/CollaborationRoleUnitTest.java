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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.collaboration.CollaborationRole.Permission;

/** Unit test for {@link CollaborationRole}. */
class CollaborationRoleUnitTest {

    @Test
    void scannerShouldOnlyShareFindings() {
        // Given
        CollaborationRole role = CollaborationRole.SCANNER;
        // Then
        assertThat(role.getPermissions(), contains(Permission.SHARE_FINDINGS));
        assertThat(role.has(Permission.SHARE_FINDINGS), is(true));
        assertThat(role.has(Permission.UPDATE_FINDINGS), is(false));
        assertThat(role.has(Permission.EXPORT_REPORTS), is(false));
    }

    @Test
    void reviewerShouldShareAndUpdateFindings() {
        // Given
        CollaborationRole role = CollaborationRole.REVIEWER;
        // Then
        assertThat(role.has(Permission.SHARE_FINDINGS), is(true));
        assertThat(role.has(Permission.UPDATE_FINDINGS), is(true));
        assertThat(role.has(Permission.EXPORT_REPORTS), is(false));
    }

    @Test
    void reporterShouldOnlyExportReports() {
        // Given
        CollaborationRole role = CollaborationRole.REPORTER;
        // Then
        assertThat(role.has(Permission.EXPORT_REPORTS), is(true));
        assertThat(role.has(Permission.SHARE_FINDINGS), is(false));
        assertThat(role.has(Permission.UPDATE_FINDINGS), is(false));
    }

    @Test
    void shouldGetRoleFromNameIgnoringCase() {
        assertThat(CollaborationRole.fromName("reviewer"), is(CollaborationRole.REVIEWER));
        assertThat(CollaborationRole.fromName(" REPORTER "), is(CollaborationRole.REPORTER));
    }

    @Test
    void shouldReturnNullForUnknownRole() {
        assertThat(CollaborationRole.fromName("unknown"), is(nullValue()));
        assertThat(CollaborationRole.fromName(null), is(nullValue()));
    }
}
