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
import java.util.Objects;
import org.parosproxy.paros.core.scanner.Alert;

/**
 * A finding shared by a member of a collaborative session.
 *
 * <p>Findings are identified by their {@link #getFingerprint() fingerprint}, so that two members
 * who report the same issue end up with a single, merged finding instead of duplicates.
 */
public class Finding {

    private final String id;
    private final String fingerprint;
    private final long createdAt;

    private String name;
    private String url;
    private String param;
    private int risk;
    private int confidence;
    private String description;
    private String solution;
    private String reference;
    private FindingStatus status;
    private String createdBy;
    private String updatedBy;
    private long updatedAt;
    private long version;

    /**
     * Constructs a {@code Finding}.
     *
     * @param id the unique identifier of the finding.
     * @param name the name of the finding.
     * @param url the URL where the finding was raised.
     * @param param the parameter, might be empty.
     * @param risk the risk, see {@link Alert#isValidRisk(int)}.
     * @param confidence the confidence, see {@link Alert#isValidConfidence(int)}.
     * @param description the description, might be empty.
     * @param solution the solution, might be empty.
     * @param reference the reference, might be empty.
     * @param createdBy the name of the member that shared the finding.
     * @param createdAt the time the finding was shared, in epoch milliseconds.
     * @throws NullPointerException if {@code id}, {@code name}, {@code url} or {@code createdBy} is
     *     {@code null}.
     * @throws IllegalArgumentException if the risk or confidence is not valid.
     */
    public Finding(
            String id,
            String name,
            String url,
            String param,
            int risk,
            int confidence,
            String description,
            String solution,
            String reference,
            String createdBy,
            long createdAt) {
        this.id = Objects.requireNonNull(id);
        this.name = Objects.requireNonNull(name);
        this.url = Objects.requireNonNull(url);
        this.param = param == null ? "" : param;
        setRisk(risk);
        setConfidence(confidence);
        this.description = description == null ? "" : description;
        this.solution = solution == null ? "" : solution;
        this.reference = reference == null ? "" : reference;
        this.status = FindingStatus.OPEN;
        this.createdBy = Objects.requireNonNull(createdBy);
        this.updatedBy = createdBy;
        this.createdAt = createdAt;
        this.updatedAt = createdAt;
        this.version = 1;
        this.fingerprint = createFingerprint(name, url, param);
    }

    /**
     * Creates the fingerprint used to detect duplicate findings.
     *
     * <p>The fingerprint is based on the name of the issue and where it was raised, so the same
     * issue raised at the same place by different members is considered a duplicate.
     *
     * @param name the name of the finding.
     * @param url the URL where the finding was raised.
     * @param param the parameter, might be {@code null}.
     * @return the fingerprint, never {@code null}.
     */
    public static String createFingerprint(String name, String url, String param) {
        return normalize(name) + '\u0000' + normalize(url) + '\u0000' + normalize(param);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    public String getId() {
        return id;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public String getParam() {
        return param;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        if (!Alert.isValidRisk(risk)) {
            throw new IllegalArgumentException("Invalid risk: " + risk);
        }
        this.risk = risk;
    }

    public int getConfidence() {
        return confidence;
    }

    public void setConfidence(int confidence) {
        if (!Alert.isValidConfidence(confidence)) {
            throw new IllegalArgumentException("Invalid confidence: " + confidence);
        }
        this.confidence = confidence;
    }

    public String getDescription() {
        return description;
    }

    public String getSolution() {
        return solution;
    }

    public String getReference() {
        return reference;
    }

    public FindingStatus getStatus() {
        return status;
    }

    public void setStatus(FindingStatus status) {
        this.status = Objects.requireNonNull(status);
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public long getVersion() {
        return version;
    }

    /**
     * Merges the given (duplicate) finding into this one.
     *
     * <p>This is the conflict resolution used when a member shares a finding that another member
     * already shared: the risk and confidence take the highest values, missing details are filled
     * in from the incoming finding and an explicit triage status takes precedence over {@link
     * FindingStatus#OPEN}. The version is incremented so the merge can be told apart from a plain
     * update.
     *
     * @param other the duplicate finding to merge.
     * @param updatedBy the name of the member whose change is being merged.
     * @param updatedAt the time of the merge, in epoch milliseconds.
     */
    public void merge(Finding other, String updatedBy, long updatedAt) {
        this.risk = Math.max(risk, other.risk);
        this.confidence = Math.max(confidence, other.confidence);
        this.description = preferNonEmpty(description, other.description);
        this.solution = preferNonEmpty(solution, other.solution);
        this.reference = preferNonEmpty(reference, other.reference);
        if (other.status != FindingStatus.OPEN) {
            this.status = other.status;
        }
        touch(updatedBy, updatedAt);
    }

    private static String preferNonEmpty(String current, String candidate) {
        if (candidate == null || candidate.isEmpty()) {
            return current;
        }
        return current == null || current.isEmpty() ? candidate : current;
    }

    /**
     * Records that the finding was changed.
     *
     * @param updatedBy the name of the member that changed the finding.
     * @param updatedAt the time of the change, in epoch milliseconds.
     */
    void touch(String updatedBy, long updatedAt) {
        this.updatedBy = Objects.requireNonNull(updatedBy);
        this.updatedAt = updatedAt;
        this.version++;
    }

    @Override
    public String toString() {
        return "Finding [id="
                + id
                + ", name="
                + name
                + ", url="
                + url
                + ", risk="
                + risk
                + ", status="
                + status
                + ", version="
                + version
                + "]";
    }
}
