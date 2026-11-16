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
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A scanning session shared by a team.
 *
 * <p>A session holds its members (each with a {@link CollaborationRole}) and the findings shared by
 * them. The class is thread safe, so that the API, the event stream and the GUI can all use it
 * concurrently.
 *
 * <p>Duplicate findings are detected through the {@link Finding#getFingerprint() fingerprint} of
 * the findings and merged, so the same issue raised by several members is kept once.
 */
public class CollaborationSession {

    /** The outcome of sharing a finding. */
    public enum ShareOutcome {
        /** The finding was not known, a new one was created. */
        CREATED,
        /** The finding was already known, it was merged into the existing one. */
        MERGED
    }

    private final String id;
    private final String name;
    private final String description;
    private final String createdBy;
    private final long createdAt;

    private final Map<String, CollaborationRole> members = new LinkedHashMap<>();
    private final Map<String, Finding> findingsByFingerprint = new LinkedHashMap<>();
    private final Map<String, Finding> findingsById = new LinkedHashMap<>();
    private final List<AuditEntry> auditTrail = new ArrayList<>();

    private long version;
    private long lastModifiedAt;

    /**
     * Constructs a {@code CollaborationSession}.
     *
     * @param id the unique identifier of the session.
     * @param name the name of the session.
     * @param description the description of the session, might be empty.
     * @param createdBy the name of the member that created the session.
     * @param createdAt the time the session was created, in epoch milliseconds.
     * @throws NullPointerException if {@code id}, {@code name} or {@code createdBy} is {@code
     *     null}.
     */
    public CollaborationSession(
            String id, String name, String description, String createdBy, long createdAt) {
        this.id = Objects.requireNonNull(id);
        this.name = Objects.requireNonNull(name);
        this.description = description == null ? "" : description;
        this.createdBy = Objects.requireNonNull(createdBy);
        this.createdAt = createdAt;
        this.lastModifiedAt = createdAt;
        this.version = 1;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    /**
     * Gets the version of the session.
     *
     * <p>The version is incremented on every change, allowing clients to tell whether their view of
     * the session is up to date.
     *
     * @return the version of the session.
     */
    public long getVersion() {
        return version;
    }

    public long getLastModifiedAt() {
        return lastModifiedAt;
    }

    /**
     * Adds a member to the session.
     *
     * @param member the name of the member.
     * @param role the role of the member.
     * @param timestamp the time the member joined, in epoch milliseconds.
     * @return {@code true} if the member was added, {@code false} if the member was already in the
     *     session.
     * @throws NullPointerException if {@code member} or {@code role} is {@code null}.
     */
    public synchronized boolean addMember(String member, CollaborationRole role, long timestamp) {
        Objects.requireNonNull(member);
        Objects.requireNonNull(role);
        if (members.putIfAbsent(member, role) != null) {
            return false;
        }
        auditTrail.add(
                new AuditEntry(timestamp, member, AuditEntry.Action.MEMBER_JOINED, role.name()));
        changed(timestamp);
        return true;
    }

    /**
     * Removes a member from the session.
     *
     * @param member the name of the member.
     * @param timestamp the time the member left, in epoch milliseconds.
     * @return {@code true} if the member was removed, {@code false} if the member was not in the
     *     session.
     */
    public synchronized boolean removeMember(String member, long timestamp) {
        if (members.remove(member) == null) {
            return false;
        }
        auditTrail.add(new AuditEntry(timestamp, member, AuditEntry.Action.MEMBER_LEFT, ""));
        changed(timestamp);
        return true;
    }

    /**
     * Gets the role of the given member.
     *
     * @param member the name of the member.
     * @return the role, or {@code null} if the member is not in the session.
     */
    public synchronized CollaborationRole getRole(String member) {
        return members.get(member);
    }

    /**
     * Gets the members of the session and their roles.
     *
     * @return an unmodifiable map with the members and roles, never {@code null}.
     */
    public synchronized Map<String, CollaborationRole> getMembers() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(members));
    }

    public synchronized int getMemberCount() {
        return members.size();
    }

    /**
     * Shares a finding in the session.
     *
     * <p>If a finding with the same {@link Finding#createFingerprint(String, String, String)
     * fingerprint} is already in the session the two are merged (see {@link Finding#merge(Finding,
     * String, long)}), otherwise the given finding is added.
     *
     * @param finding the finding to share.
     * @param timestamp the time the finding was shared, in epoch milliseconds.
     * @return the outcome of the operation.
     * @throws NullPointerException if {@code finding} is {@code null}.
     */
    public synchronized ShareOutcome shareFinding(Finding finding, long timestamp) {
        Objects.requireNonNull(finding);
        Finding existing = findingsByFingerprint.get(finding.getFingerprint());
        if (existing != null) {
            existing.merge(finding, finding.getCreatedBy(), timestamp);
            auditTrail.add(
                    new AuditEntry(
                            timestamp,
                            finding.getCreatedBy(),
                            AuditEntry.Action.FINDING_MERGED,
                            existing.getId()));
            changed(timestamp);
            return ShareOutcome.MERGED;
        }

        findingsByFingerprint.put(finding.getFingerprint(), finding);
        findingsById.put(finding.getId(), finding);
        auditTrail.add(
                new AuditEntry(
                        timestamp,
                        finding.getCreatedBy(),
                        AuditEntry.Action.FINDING_SHARED,
                        finding.getId()));
        changed(timestamp);
        return ShareOutcome.CREATED;
    }

    /**
     * Gets the finding with the given identifier.
     *
     * @param findingId the identifier of the finding.
     * @return the finding, or {@code null} if not found.
     */
    public synchronized Finding getFinding(String findingId) {
        return findingsById.get(findingId);
    }

    /**
     * Gets the findings of the session, ordered by the time they were shared.
     *
     * @return an unmodifiable list with the findings, never {@code null}.
     */
    public synchronized List<Finding> getFindings() {
        return Collections.unmodifiableList(new ArrayList<>(findingsById.values()));
    }

    public synchronized int getFindingCount() {
        return findingsById.size();
    }

    /**
     * Records that the given finding was changed.
     *
     * @param finding the finding that was changed.
     * @param member the name of the member that changed the finding.
     * @param timestamp the time of the change, in epoch milliseconds.
     */
    public synchronized void findingUpdated(Finding finding, String member, long timestamp) {
        finding.touch(member, timestamp);
        auditTrail.add(
                new AuditEntry(
                        timestamp, member, AuditEntry.Action.FINDING_UPDATED, finding.getId()));
        changed(timestamp);
    }

    /**
     * Gets the audit trail of the session.
     *
     * @return an unmodifiable list with the audit entries, in chronological order, never {@code
     *     null}.
     */
    public synchronized List<AuditEntry> getAuditTrail() {
        return Collections.unmodifiableList(new ArrayList<>(auditTrail));
    }

    private void changed(long timestamp) {
        lastModifiedAt = timestamp;
        version++;
    }

    /**
     * Gets the findings of the session grouped by their triage status.
     *
     * @return an unmodifiable map with the findings grouped by status, never {@code null}.
     */
    public synchronized Map<FindingStatus, List<Finding>> getFindingsByStatus() {
        Map<FindingStatus, List<Finding>> byStatus = new LinkedHashMap<>();
        for (FindingStatus status : FindingStatus.values()) {
            byStatus.put(status, new ArrayList<>());
        }
        for (Finding finding : findingsById.values()) {
            byStatus.get(finding.getStatus()).add(finding);
        }
        return Collections.unmodifiableMap(byStatus);
    }

    /**
     * Gets the findings of the given status.
     *
     * @param status the status of the findings.
     * @return an unmodifiable list with the findings, never {@code null}.
     */
    public synchronized List<Finding> getFindings(FindingStatus status) {
        Objects.requireNonNull(status);
        List<Finding> result = new ArrayList<>();
        for (Finding finding : findingsById.values()) {
            if (finding.getStatus() == status) {
                result.add(finding);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * Tells whether or not the given member is in the session.
     *
     * @param member the name of the member.
     * @return {@code true} if the member is in the session, {@code false} otherwise.
     */
    public synchronized boolean hasMember(String member) {
        return members.containsKey(member);
    }

    /**
     * Gets the names of the members of the session.
     *
     * @return an unmodifiable collection with the names of the members, never {@code null}.
     */
    public synchronized Collection<String> getMemberNames() {
        return Collections.unmodifiableCollection(new ArrayList<>(members.keySet()));
    }

    /**
     * Gets the finding with the given fingerprint.
     *
     * @param fingerprint the fingerprint of the finding.
     * @return the finding, or {@link Optional#empty()} if not found.
     */
    public synchronized Optional<Finding> getFindingByFingerprint(String fingerprint) {
        return Optional.ofNullable(findingsByFingerprint.get(fingerprint));
    }
}
