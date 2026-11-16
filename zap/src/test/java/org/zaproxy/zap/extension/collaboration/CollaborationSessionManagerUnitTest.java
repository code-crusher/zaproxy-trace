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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.eventBus.Event;

/** Unit test for {@link CollaborationSessionManager}. */
class CollaborationSessionManagerUnitTest {

    private static final String ALICE = "alice";
    private static final String BOB = "bob";
    private static final String CAROL = "carol";

    private AtomicLong clock;
    private List<Event> events;
    private CollaborationSessionManager manager;

    @BeforeEach
    void setUp() {
        clock = new AtomicLong(1000);
        events = new ArrayList<>();
        manager =
                new CollaborationSessionManager(
                        new InMemoryCollaborationSessionStore(), events::add, clock::get);
    }

    @Test
    void shouldCreateSessionWithOwnerAsScanner() throws Exception {
        // When
        CollaborationSession session = manager.createSession("Engagement", "desc", ALICE);
        // Then
        assertThat(session.getName(), is(equalTo("Engagement")));
        assertThat(session.getDescription(), is(equalTo("desc")));
        assertThat(session.getCreatedBy(), is(equalTo(ALICE)));
        assertThat(session.getRole(ALICE), is(equalTo(CollaborationRole.SCANNER)));
        assertThat(manager.getSessions(), hasSize(1));
        assertThat(events, hasSize(1));
        assertThat(
                events.get(0).getEventType(),
                is(equalTo(CollaborationEventPublisher.SESSION_CREATED)));
    }

    @Test
    void shouldRejectSessionWithoutName() {
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class, () -> manager.createSession(" ", "", ALICE));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.INVALID_DATA)));
    }

    @Test
    void shouldRejectSessionWithoutOwner() {
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () -> manager.createSession("Engagement", "", null));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.INVALID_DATA)));
    }

    @Test
    void shouldFailToGetUnknownSession() {
        // When
        CollaborationException e =
                assertThrows(CollaborationException.class, () -> manager.getSession("unknown"));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.SESSION_NOT_FOUND)));
    }

    @Test
    void shouldJoinAndLeaveSession() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        events.clear();
        // When
        manager.joinSession(session.getId(), BOB, CollaborationRole.REVIEWER);
        // Then
        assertThat(session.getRole(BOB), is(equalTo(CollaborationRole.REVIEWER)));
        assertThat(
                events.get(0).getEventType(),
                is(equalTo(CollaborationEventPublisher.MEMBER_JOINED)));
        // When
        manager.leaveSession(session.getId(), BOB);
        // Then
        assertThat(session.getRole(BOB), is(nullValue()));
        assertThat(
                events.get(1).getEventType(), is(equalTo(CollaborationEventPublisher.MEMBER_LEFT)));
    }

    @Test
    void shouldRejectJoiningTwice() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () ->
                                manager.joinSession(
                                        session.getId(), ALICE, CollaborationRole.REVIEWER));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.INVALID_DATA)));
    }

    @Test
    void shouldRejectLeavingWhenNotAMember() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () -> manager.leaveSession(session.getId(), BOB));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.MEMBER_NOT_FOUND)));
    }

    @Test
    void shouldShareFindingAndRecordAuditTrail() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        // When
        Finding finding =
                manager.shareFinding(
                        session.getId(),
                        ALICE,
                        "SQL Injection",
                        "https://example.com/login",
                        "user",
                        Alert.RISK_HIGH,
                        Alert.CONFIDENCE_MEDIUM,
                        "desc",
                        "solution",
                        "reference");
        // Then
        assertThat(session.getFindings(), hasSize(1));
        assertThat(finding.getStatus(), is(equalTo(FindingStatus.OPEN)));
        assertThat(finding.getCreatedBy(), is(equalTo(ALICE)));
        assertThat(
                session.getAuditTrail().get(session.getAuditTrail().size() - 1).getAction(),
                is(equalTo(AuditEntry.Action.FINDING_SHARED)));
        assertThat(
                events.get(events.size() - 1).getEventType(),
                is(equalTo(CollaborationEventPublisher.FINDING_SHARED)));
    }

    @Test
    void shouldMergeDuplicateFindingsSharedByDifferentMembers() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.SCANNER);
        Finding first =
                manager.shareFinding(
                        session.getId(),
                        ALICE,
                        "SQL Injection",
                        "https://example.com/login",
                        "user",
                        Alert.RISK_LOW,
                        Alert.CONFIDENCE_LOW,
                        "",
                        "",
                        "");
        events.clear();
        // When
        Finding second =
                manager.shareFinding(
                        session.getId(),
                        BOB,
                        "sql injection",
                        "https://example.com/login ",
                        "user",
                        Alert.RISK_HIGH,
                        Alert.CONFIDENCE_HIGH,
                        "details",
                        "solution",
                        "");
        // Then
        assertThat(session.getFindings(), hasSize(1));
        assertThat(second.getId(), is(equalTo(first.getId())));
        assertThat(second.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(second.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(second.getDescription(), is(equalTo("details")));
        assertThat(second.getSolution(), is(equalTo("solution")));
        assertThat(second.getVersion(), is(equalTo(2L)));
        assertThat(
                events.get(events.size() - 1).getEventType(),
                is(equalTo(CollaborationEventPublisher.FINDING_MERGED)));
    }

    @Test
    void shouldNotMergeFindingsWithDifferentFingerprints() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.shareFinding(
                session.getId(), ALICE, "XSS", "https://example.com/a", "", 1, 1, "", "", "");
        // When
        manager.shareFinding(
                session.getId(), ALICE, "XSS", "https://example.com/b", "", 1, 1, "", "", "");
        // Then
        assertThat(session.getFindings(), hasSize(2));
    }

    @Test
    void shouldRejectSharingFindingWhenNotAMember() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () ->
                                manager.shareFinding(
                                        session.getId(),
                                        BOB,
                                        "XSS",
                                        "https://example.com",
                                        "",
                                        1,
                                        1,
                                        "",
                                        "",
                                        ""));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.MEMBER_NOT_FOUND)));
    }

    @Test
    void shouldRejectSharingFindingWithInvalidRisk() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () ->
                                manager.shareFinding(
                                        session.getId(),
                                        ALICE,
                                        "XSS",
                                        "https://example.com",
                                        "",
                                        99,
                                        1,
                                        "",
                                        "",
                                        ""));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.INVALID_DATA)));
    }

    @Test
    void shouldUpdateFindingWhenReviewer() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.REVIEWER);
        Finding finding =
                manager.shareFinding(
                        session.getId(), ALICE, "XSS", "https://example.com", "", 1, 1, "", "", "");
        events.clear();
        // When
        manager.updateFinding(session.getId(), BOB, finding.getId(), FindingStatus.FALSE_POSITIVE);
        // Then
        assertThat(finding.getStatus(), is(equalTo(FindingStatus.FALSE_POSITIVE)));
        assertThat(finding.getUpdatedBy(), is(equalTo(BOB)));
        assertThat(session.getFindings(FindingStatus.FALSE_POSITIVE), hasSize(1));
        assertThat(
                events.get(0).getEventType(),
                is(equalTo(CollaborationEventPublisher.FINDING_UPDATED)));
    }

    @Test
    void shouldRejectUpdateWhenScanner() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        Finding finding =
                manager.shareFinding(
                        session.getId(), ALICE, "XSS", "https://example.com", "", 1, 1, "", "", "");
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () ->
                                manager.updateFinding(
                                        session.getId(),
                                        ALICE,
                                        finding.getId(),
                                        FindingStatus.CONFIRMED));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.NOT_ALLOWED)));
        assertThat(finding.getStatus(), is(equalTo(FindingStatus.OPEN)));
    }

    @Test
    void shouldRejectUpdateOfUnknownFinding() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.REVIEWER);
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () ->
                                manager.updateFinding(
                                        session.getId(), BOB, "unknown", FindingStatus.CONFIRMED));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.FINDING_NOT_FOUND)));
    }

    @Test
    void shouldDeleteSessionWhenReviewer() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.REVIEWER);
        // When
        manager.deleteSession(session.getId(), BOB);
        // Then
        assertThat(manager.getSessions(), is(empty()));
    }

    @Test
    void shouldRejectDeleteWhenScanner() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        // When
        CollaborationException e =
                assertThrows(
                        CollaborationException.class,
                        () -> manager.deleteSession(session.getId(), ALICE));
        // Then
        assertThat(e.getKind(), is(equalTo(CollaborationException.Kind.NOT_ALLOWED)));
        assertThat(manager.getSessions(), is(not(empty())));
    }

    @Test
    void shouldIncrementVersionOnChanges() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        long version = session.getVersion();
        // When
        manager.shareFinding(
                session.getId(), ALICE, "XSS", "https://example.com", "", 1, 1, "", "", "");
        // Then
        assertThat(session.getVersion(), is(equalTo(version + 1)));
    }

    @Test
    void shouldUseGivenStore() throws Exception {
        // Given
        InMemoryCollaborationSessionStore store = new InMemoryCollaborationSessionStore();
        CollaborationSessionManager managerWithStore =
                new CollaborationSessionManager(store, events::add, clock::get);
        CollaborationSession session = managerWithStore.createSession("Engagement", "", ALICE);
        // Then
        assertThat(store.get(session.getId()), is(equalTo(session)));
    }
}
