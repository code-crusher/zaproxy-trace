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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;

/** Unit test for {@link CollaborationSession}. */
class CollaborationSessionUnitTest {

    private static final String SESSION_ID = "session";
    private static final String MEMBER = "alice";
    private static final long TIME = 1000;

    private CollaborationSession createSession() {
        return new CollaborationSession(SESSION_ID, "name", "", MEMBER, TIME);
    }

    private static Finding createFinding(String id, String name, String url) {
        return new Finding(
                id,
                name,
                url,
                "",
                Alert.RISK_MEDIUM,
                Alert.CONFIDENCE_MEDIUM,
                "",
                "",
                "",
                MEMBER,
                TIME);
    }

    @Test
    void shouldCreateSessionWithVersionOne() {
        // When
        CollaborationSession session = createSession();
        // Then
        assertThat(session.getId(), is(equalTo(SESSION_ID)));
        assertThat(session.getVersion(), is(equalTo(1L)));
        assertThat(session.getFindingCount(), is(equalTo(0)));
        assertThat(session.getMemberCount(), is(equalTo(0)));
    }

    @Test
    void shouldAddMemberOnce() {
        // Given
        CollaborationSession session = createSession();
        // When
        boolean added = session.addMember(MEMBER, CollaborationRole.SCANNER, TIME);
        boolean addedAgain = session.addMember(MEMBER, CollaborationRole.REVIEWER, TIME);
        // Then
        assertThat(added, is(equalTo(true)));
        assertThat(addedAgain, is(equalTo(false)));
        assertThat(session.getRole(MEMBER), is(equalTo(CollaborationRole.SCANNER)));
    }

    @Test
    void shouldRemoveMember() {
        // Given
        CollaborationSession session = createSession();
        session.addMember(MEMBER, CollaborationRole.SCANNER, TIME);
        // When
        boolean removed = session.removeMember(MEMBER, TIME);
        boolean removedAgain = session.removeMember(MEMBER, TIME);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(removedAgain, is(equalTo(false)));
        assertThat(session.hasMember(MEMBER), is(equalTo(false)));
    }

    @Test
    void shouldShareFinding() {
        // Given
        CollaborationSession session = createSession();
        Finding finding = createFinding("1", "XSS", "https://example.com");
        // When
        CollaborationSession.ShareOutcome outcome = session.shareFinding(finding, TIME);
        // Then
        assertThat(outcome, is(equalTo(CollaborationSession.ShareOutcome.CREATED)));
        assertThat(session.getFinding("1"), is(sameInstance(finding)));
        assertThat(session.getFindings(), contains(finding));
    }

    @Test
    void shouldMergeFindingWithSameFingerprint() {
        // Given
        CollaborationSession session = createSession();
        Finding first = createFinding("1", "XSS", "https://example.com");
        Finding duplicate = createFinding("2", "xss", "https://example.com");
        session.shareFinding(first, TIME);
        // When
        CollaborationSession.ShareOutcome outcome = session.shareFinding(duplicate, TIME);
        // Then
        assertThat(outcome, is(equalTo(CollaborationSession.ShareOutcome.MERGED)));
        assertThat(session.getFindingCount(), is(equalTo(1)));
        assertThat(session.getFinding("1"), is(sameInstance(first)));
    }

    @Test
    void shouldKeepHighestRiskAndConfidenceWhenMerging() {
        // Given
        CollaborationSession session = createSession();
        Finding low = createFinding("1", "XSS", "https://example.com");
        Finding high =
                new Finding(
                        "2",
                        "XSS",
                        "https://example.com",
                        "",
                        Alert.RISK_HIGH,
                        Alert.CONFIDENCE_HIGH,
                        "",
                        "",
                        "",
                        MEMBER,
                        TIME);
        session.shareFinding(low, TIME);
        // When
        session.shareFinding(high, TIME);
        // Then
        assertThat(low.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(low.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
    }

    @Test
    void shouldPreferExplicitStatusWhenMerging() {
        // Given
        CollaborationSession session = createSession();
        Finding confirmed = createFinding("1", "XSS", "https://example.com");
        confirmed.setStatus(FindingStatus.CONFIRMED);
        Finding open = createFinding("2", "XSS", "https://example.com");
        session.shareFinding(confirmed, TIME);
        // When
        session.shareFinding(open, TIME);
        // Then
        assertThat(confirmed.getStatus(), is(equalTo(FindingStatus.CONFIRMED)));
    }

    @Test
    void shouldRecordAuditTrail() {
        // Given
        CollaborationSession session = createSession();
        session.addMember(MEMBER, CollaborationRole.SCANNER, TIME);
        session.shareFinding(createFinding("1", "XSS", "https://example.com"), TIME);
        // When
        List<AuditEntry> auditTrail = session.getAuditTrail();
        // Then
        assertThat(auditTrail, hasSize(2));
        assertThat(auditTrail.get(0).getAction(), is(equalTo(AuditEntry.Action.MEMBER_JOINED)));
        assertThat(auditTrail.get(1).getAction(), is(equalTo(AuditEntry.Action.FINDING_SHARED)));
    }

    @Test
    void shouldGroupFindingsByStatus() {
        // Given
        CollaborationSession session = createSession();
        Finding open = createFinding("1", "XSS", "https://example.com");
        Finding confirmed = createFinding("2", "SQLi", "https://example.com");
        confirmed.setStatus(FindingStatus.CONFIRMED);
        session.shareFinding(open, TIME);
        session.shareFinding(confirmed, TIME);
        // Then
        assertThat(session.getFindingsByStatus().get(FindingStatus.OPEN), contains(open));
        assertThat(session.getFindingsByStatus().get(FindingStatus.CONFIRMED), contains(confirmed));
        assertThat(session.getFindings(FindingStatus.OPEN), contains(open));
    }

    @Test
    void shouldFindByFingerprint() {
        // Given
        CollaborationSession session = createSession();
        Finding finding = createFinding("1", "XSS", "https://example.com");
        session.shareFinding(finding, TIME);
        // Then
        assertThat(
                session.getFindingByFingerprint(finding.getFingerprint()).orElse(null),
                is(sameInstance(finding)));
    }
}
