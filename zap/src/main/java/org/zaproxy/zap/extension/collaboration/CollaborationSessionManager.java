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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;

/**
 * Manages the collaborative sessions of the team.
 *
 * <p>This class owns the {@link CollaborationSessionStore store} of the sessions, enforces the
 * {@link CollaborationRole role} based access control and publishes the changes through the event
 * bus so that they can be synchronised in real time.
 *
 * <p>The current time is obtained through the {@code clock} given at construction time, which makes
 * the behaviour easy to test.
 */
public class CollaborationSessionManager {

    private final CollaborationSessionStore store;
    private final Consumer<Event> eventPublisher;
    private final LongSupplier clock;

    /**
     * Constructs a {@code CollaborationSessionManager} with the default store and the ZAP event
     * bus.
     */
    public CollaborationSessionManager() {
        this(
                new InMemoryCollaborationSessionStore(),
                event -> ZAP.getEventBus().publishSyncEvent(event.getPublisher(), event),
                System::currentTimeMillis);
    }

    /**
     * Constructs a {@code CollaborationSessionManager}.
     *
     * @param store the store of the sessions.
     * @param eventPublisher the consumer of the events to publish.
     * @param clock the supplier of the current time, in epoch milliseconds.
     * @throws NullPointerException if any of the parameters is {@code null}.
     */
    public CollaborationSessionManager(
            CollaborationSessionStore store, Consumer<Event> eventPublisher, LongSupplier clock) {
        this.store = Objects.requireNonNull(store);
        this.eventPublisher = Objects.requireNonNull(eventPublisher);
        this.clock = Objects.requireNonNull(clock);
        CollaborationEventPublisher.getPublisher();
    }

    public CollaborationSessionStore getStore() {
        return store;
    }

    /**
     * Creates a session.
     *
     * @param name the name of the session.
     * @param description the description of the session, might be empty.
     * @param owner the name of the member that creates the session, who joins it as a {@link
     *     CollaborationRole#SCANNER scanner}.
     * @return the created session, never {@code null}.
     * @throws CollaborationException if the name or the owner is empty.
     */
    public CollaborationSession createSession(String name, String description, String owner)
            throws CollaborationException {
        requireNonEmpty(name, "name");
        requireNonEmpty(owner, "owner");

        long now = clock.getAsLong();
        CollaborationSession session =
                new CollaborationSession(
                        UUID.randomUUID().toString(), name, description, owner, now);
        session.addMember(owner, CollaborationRole.SCANNER, now);
        store.save(session);
        publish(
                CollaborationEventPublisher.SESSION_CREATED,
                session,
                owner,
                Map.of(CollaborationEventPublisher.ROLE, CollaborationRole.SCANNER.name()));
        return session;
    }

    /**
     * Gets a session.
     *
     * @param sessionId the identifier of the session.
     * @return the session, never {@code null}.
     * @throws CollaborationException if the session does not exist.
     */
    public CollaborationSession getSession(String sessionId) throws CollaborationException {
        CollaborationSession session = store.get(sessionId);
        if (session == null) {
            throw new CollaborationException(
                    CollaborationException.Kind.SESSION_NOT_FOUND, sessionId);
        }
        return session;
    }

    /**
     * Gets the sessions, ordered by creation time.
     *
     * @return an unmodifiable list with the sessions, never {@code null}.
     */
    public List<CollaborationSession> getSessions() {
        List<CollaborationSession> sessions = new ArrayList<>(store.getAll());
        sessions.sort(Comparator.comparingLong(CollaborationSession::getCreatedAt));
        return Collections.unmodifiableList(sessions);
    }

    /**
     * Deletes a session.
     *
     * @param sessionId the identifier of the session.
     * @param member the name of the member deleting the session.
     * @return the deleted session, never {@code null}.
     * @throws CollaborationException if the session does not exist or the member is not a {@link
     *     CollaborationRole#REVIEWER reviewer} of it.
     */
    public CollaborationSession deleteSession(String sessionId, String member)
            throws CollaborationException {
        CollaborationSession session = getSession(sessionId);
        requirePermission(session, member, CollaborationRole.Permission.UPDATE_FINDINGS);
        store.remove(sessionId);
        publish(CollaborationEventPublisher.SESSION_DELETED, session, member, Map.of());
        return session;
    }

    /**
     * Adds a member to a session.
     *
     * @param sessionId the identifier of the session.
     * @param member the name of the member joining.
     * @param role the role of the member.
     * @return the session, never {@code null}.
     * @throws CollaborationException if the session does not exist, the member or role is invalid
     *     or the member is already in the session.
     */
    public CollaborationSession joinSession(String sessionId, String member, CollaborationRole role)
            throws CollaborationException {
        requireNonEmpty(member, "member");
        if (role == null) {
            throw new CollaborationException(CollaborationException.Kind.INVALID_DATA, "role");
        }

        CollaborationSession session = getSession(sessionId);
        if (!session.addMember(member, role, clock.getAsLong())) {
            throw new CollaborationException(
                    CollaborationException.Kind.INVALID_DATA,
                    "Member already in the session: " + member);
        }
        publish(
                CollaborationEventPublisher.MEMBER_JOINED,
                session,
                member,
                Map.of(CollaborationEventPublisher.ROLE, role.name()));
        return session;
    }

    /**
     * Removes a member from a session.
     *
     * @param sessionId the identifier of the session.
     * @param member the name of the member leaving.
     * @return the session, never {@code null}.
     * @throws CollaborationException if the session does not exist or the member is not in it.
     */
    public CollaborationSession leaveSession(String sessionId, String member)
            throws CollaborationException {
        CollaborationSession session = getSession(sessionId);
        if (!session.removeMember(member, clock.getAsLong())) {
            throw new CollaborationException(CollaborationException.Kind.MEMBER_NOT_FOUND, member);
        }
        publish(
                CollaborationEventPublisher.MEMBER_LEFT,
                session,
                member,
                Map.of(CollaborationEventPublisher.MEMBER, member));
        return session;
    }

    /**
     * Shares a finding in a session.
     *
     * <p>Only members with the {@link CollaborationRole.Permission#SHARE_FINDINGS SHARE_FINDINGS}
     * permission may share findings. Duplicate findings are merged.
     *
     * @param sessionId the identifier of the session.
     * @param member the name of the member sharing the finding.
     * @param name the name of the finding.
     * @param url the URL where the finding was raised.
     * @param param the parameter, might be empty.
     * @param risk the risk.
     * @param confidence the confidence.
     * @param description the description, might be empty.
     * @param solution the solution, might be empty.
     * @param reference the reference, might be empty.
     * @return the resulting finding (new or merged), never {@code null}.
     * @throws CollaborationException if the session does not exist, the member is not allowed to
     *     share findings or the data is invalid.
     */
    public Finding shareFinding(
            String sessionId,
            String member,
            String name,
            String url,
            String param,
            int risk,
            int confidence,
            String description,
            String solution,
            String reference)
            throws CollaborationException {
        requireNonEmpty(name, "name");
        requireNonEmpty(url, "url");

        CollaborationSession session = getSession(sessionId);
        requirePermission(session, member, CollaborationRole.Permission.SHARE_FINDINGS);

        long now = clock.getAsLong();
        Finding finding;
        try {
            finding =
                    new Finding(
                            UUID.randomUUID().toString(),
                            name,
                            url,
                            param,
                            risk,
                            confidence,
                            description,
                            solution,
                            reference,
                            member,
                            now);
        } catch (IllegalArgumentException e) {
            throw new CollaborationException(
                    CollaborationException.Kind.INVALID_DATA, e.getMessage());
        }

        CollaborationSession.ShareOutcome outcome = session.shareFinding(finding, now);
        Finding result =
                outcome == CollaborationSession.ShareOutcome.MERGED
                        ? session.getFindingByFingerprint(finding.getFingerprint()).orElse(finding)
                        : finding;
        publish(
                outcome == CollaborationSession.ShareOutcome.MERGED
                        ? CollaborationEventPublisher.FINDING_MERGED
                        : CollaborationEventPublisher.FINDING_SHARED,
                session,
                member,
                Map.of(CollaborationEventPublisher.FINDING_ID, result.getId()));
        return result;
    }

    /**
     * Updates the triage status of a finding.
     *
     * <p>Only members with the {@link CollaborationRole.Permission#UPDATE_FINDINGS UPDATE_FINDINGS}
     * permission may update findings.
     *
     * @param sessionId the identifier of the session.
     * @param member the name of the member updating the finding.
     * @param findingId the identifier of the finding.
     * @param status the new status.
     * @return the updated finding, never {@code null}.
     * @throws CollaborationException if the session or the finding does not exist or the member is
     *     not allowed to update findings.
     */
    public Finding updateFinding(
            String sessionId, String member, String findingId, FindingStatus status)
            throws CollaborationException {
        if (status == null) {
            throw new CollaborationException(CollaborationException.Kind.INVALID_DATA, "status");
        }

        CollaborationSession session = getSession(sessionId);
        requirePermission(session, member, CollaborationRole.Permission.UPDATE_FINDINGS);

        Finding finding = session.getFinding(findingId);
        if (finding == null) {
            throw new CollaborationException(
                    CollaborationException.Kind.FINDING_NOT_FOUND, findingId);
        }

        finding.setStatus(status);
        session.findingUpdated(finding, member, clock.getAsLong());
        publish(
                CollaborationEventPublisher.FINDING_UPDATED,
                session,
                member,
                Map.of(CollaborationEventPublisher.FINDING_ID, finding.getId()));
        return finding;
    }

    private static void requireNonEmpty(String value, String name) throws CollaborationException {
        if (value == null || value.trim().isEmpty()) {
            throw new CollaborationException(CollaborationException.Kind.INVALID_DATA, name);
        }
    }

    private static void requirePermission(
            CollaborationSession session, String member, CollaborationRole.Permission permission)
            throws CollaborationException {
        CollaborationRole role = session.getRole(member);
        if (role == null) {
            throw new CollaborationException(CollaborationException.Kind.MEMBER_NOT_FOUND, member);
        }
        if (!role.has(permission)) {
            throw new CollaborationException(
                    CollaborationException.Kind.NOT_ALLOWED,
                    "Role " + role + " does not grant " + permission);
        }
    }

    private void publish(
            String eventType,
            CollaborationSession session,
            String member,
            Map<String, String> extraParameters) {
        Map<String, String> parameters = new HashMap<>(extraParameters);
        parameters.put(CollaborationEventPublisher.SESSION_ID, session.getId());
        parameters.put(CollaborationEventPublisher.MEMBER, member);
        eventPublisher.accept(
                new Event(CollaborationEventPublisher.getPublisher(), eventType, null, parameters));
    }
}
