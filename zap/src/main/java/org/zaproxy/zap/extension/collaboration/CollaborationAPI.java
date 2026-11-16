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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpInputStream;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpOutputStream;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiPersistentConnection;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.utils.ApiUtils;

/**
 * The API of the collaborative scan sessions.
 *
 * <p>Besides the usual actions and views, it provides a {@code pconn} endpoint that streams the
 * changes of a session as Server-Sent Events, which is what lets the members of a team see the
 * findings of each other in real time.
 */
public class CollaborationAPI extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(CollaborationAPI.class);

    private static final String PREFIX = "collaboration";

    private static final String ACTION_CREATE_SESSION = "createSession";
    private static final String ACTION_DELETE_SESSION = "deleteSession";
    private static final String ACTION_JOIN_SESSION = "joinSession";
    private static final String ACTION_LEAVE_SESSION = "leaveSession";
    private static final String ACTION_SHARE_FINDING = "shareFinding";
    private static final String ACTION_UPDATE_FINDING = "updateFinding";

    private static final String VIEW_GET_SESSIONS = "getSessions";
    private static final String VIEW_GET_SESSION = "getSession";
    private static final String VIEW_GET_FINDINGS = "getFindings";
    private static final String VIEW_GET_AUDIT_TRAIL = "getAuditTrail";
    private static final String VIEW_GET_REPORT = "getReport";

    private static final String PCONN_SESSION_EVENTS = "sessionEvents";

    private static final String PARAM_SESSION_ID = "sessionId";
    private static final String PARAM_NAME = "name";
    private static final String PARAM_DESCRIPTION = "description";
    private static final String PARAM_MEMBER = "member";
    private static final String PARAM_ROLE = "role";
    private static final String PARAM_URL = "url";
    private static final String PARAM_PARAM = "param";
    private static final String PARAM_RISK = "risk";
    private static final String PARAM_CONFIDENCE = "confidence";
    private static final String PARAM_SOLUTION = "solution";
    private static final String PARAM_REFERENCE = "reference";
    private static final String PARAM_FINDING_ID = "findingId";
    private static final String PARAM_STATUS = "status";
    private static final String PARAM_POLL = "poll";
    private static final String PARAM_KEEP_ALIVE = "keepAlive";

    private final CollaborationSessionManager sessionManager;

    /**
     * Constructs a {@code CollaborationAPI}.
     *
     * @param sessionManager the manager of the collaborative sessions, might be {@code null} if the
     *     API is used only to generate the API definitions.
     */
    public CollaborationAPI(CollaborationSessionManager sessionManager) {
        this.sessionManager = sessionManager;

        this.addApiAction(
                new ApiAction(
                        ACTION_CREATE_SESSION,
                        new String[] {PARAM_NAME},
                        new String[] {PARAM_DESCRIPTION}));
        this.addApiAction(
                new ApiAction(
                        ACTION_DELETE_SESSION, new String[] {PARAM_SESSION_ID, PARAM_MEMBER}));
        this.addApiAction(
                new ApiAction(
                        ACTION_JOIN_SESSION,
                        new String[] {PARAM_SESSION_ID, PARAM_MEMBER, PARAM_ROLE}));
        this.addApiAction(
                new ApiAction(ACTION_LEAVE_SESSION, new String[] {PARAM_SESSION_ID, PARAM_MEMBER}));
        this.addApiAction(
                new ApiAction(
                        ACTION_SHARE_FINDING,
                        new String[] {PARAM_SESSION_ID, PARAM_MEMBER, PARAM_NAME, PARAM_URL},
                        new String[] {
                            PARAM_PARAM,
                            PARAM_RISK,
                            PARAM_CONFIDENCE,
                            PARAM_DESCRIPTION,
                            PARAM_SOLUTION,
                            PARAM_REFERENCE
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_UPDATE_FINDING,
                        new String[] {
                            PARAM_SESSION_ID, PARAM_MEMBER, PARAM_FINDING_ID, PARAM_STATUS
                        }));

        this.addApiView(new ApiView(VIEW_GET_SESSIONS));
        this.addApiView(new ApiView(VIEW_GET_SESSION, new String[] {PARAM_SESSION_ID}));
        this.addApiView(
                new ApiView(
                        VIEW_GET_FINDINGS,
                        new String[] {PARAM_SESSION_ID},
                        new String[] {PARAM_STATUS}));
        this.addApiView(new ApiView(VIEW_GET_AUDIT_TRAIL, new String[] {PARAM_SESSION_ID}));
        this.addApiView(new ApiView(VIEW_GET_REPORT, new String[] {PARAM_SESSION_ID}));

        this.addApiPersistentConnection(
                new ApiPersistentConnection(
                        PCONN_SESSION_EVENTS,
                        new String[] {PARAM_SESSION_ID},
                        new String[] {PARAM_POLL, PARAM_KEEP_ALIVE}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        try {
            switch (name) {
                case ACTION_CREATE_SESSION:
                    return getSessionResponse(
                            sessionManager.createSession(
                                    params.getString(PARAM_NAME),
                                    ApiUtils.getOptionalStringParam(params, PARAM_DESCRIPTION),
                                    getMember(params)));

                case ACTION_DELETE_SESSION:
                    return getSessionResponse(
                            sessionManager.deleteSession(
                                    params.getString(PARAM_SESSION_ID), getMember(params)));

                case ACTION_JOIN_SESSION:
                    return getSessionResponse(
                            sessionManager.joinSession(
                                    params.getString(PARAM_SESSION_ID),
                                    getMember(params),
                                    getRole(params)));

                case ACTION_LEAVE_SESSION:
                    return getSessionResponse(
                            sessionManager.leaveSession(
                                    params.getString(PARAM_SESSION_ID), getMember(params)));

                case ACTION_SHARE_FINDING:
                    return getFindingResponse(
                            sessionManager.shareFinding(
                                    params.getString(PARAM_SESSION_ID),
                                    getMember(params),
                                    params.getString(PARAM_NAME),
                                    params.getString(PARAM_URL),
                                    ApiUtils.getOptionalStringParam(params, PARAM_PARAM),
                                    getParam(params, PARAM_RISK, Alert.RISK_MEDIUM),
                                    getParam(params, PARAM_CONFIDENCE, Alert.CONFIDENCE_MEDIUM),
                                    ApiUtils.getOptionalStringParam(params, PARAM_DESCRIPTION),
                                    ApiUtils.getOptionalStringParam(params, PARAM_SOLUTION),
                                    ApiUtils.getOptionalStringParam(params, PARAM_REFERENCE)));

                case ACTION_UPDATE_FINDING:
                    return getFindingResponse(
                            sessionManager.updateFinding(
                                    params.getString(PARAM_SESSION_ID),
                                    getMember(params),
                                    params.getString(PARAM_FINDING_ID),
                                    getStatus(params)));

                default:
                    throw new ApiException(ApiException.Type.BAD_ACTION);
            }
        } catch (CollaborationException e) {
            throw toApiException(e);
        }
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        try {
            switch (name) {
                case VIEW_GET_SESSIONS:
                    ApiResponseList sessions = new ApiResponseList(name);
                    for (CollaborationSession session : sessionManager.getSessions()) {
                        sessions.addItem(getSessionResponse(session));
                    }
                    return sessions;

                case VIEW_GET_SESSION:
                    return getSessionResponse(
                            sessionManager.getSession(params.getString(PARAM_SESSION_ID)));

                case VIEW_GET_FINDINGS:
                    CollaborationSession session =
                            sessionManager.getSession(params.getString(PARAM_SESSION_ID));
                    String status = ApiUtils.getOptionalStringParam(params, PARAM_STATUS);
                    List<Finding> findings =
                            status == null
                                    ? session.getFindings()
                                    : session.getFindings(getStatus(params));
                    ApiResponseList findingsResponse = new ApiResponseList(name);
                    for (Finding finding : findings) {
                        findingsResponse.addItem(getFindingResponse(finding));
                    }
                    return findingsResponse;

                case VIEW_GET_AUDIT_TRAIL:
                    CollaborationSession audited =
                            sessionManager.getSession(params.getString(PARAM_SESSION_ID));
                    ApiResponseList auditTrail = new ApiResponseList(name);
                    for (AuditEntry entry : audited.getAuditTrail()) {
                        auditTrail.addItem(getAuditEntryResponse(entry));
                    }
                    return auditTrail;

                case VIEW_GET_REPORT:
                    return getReportResponse(
                            sessionManager.getSession(params.getString(PARAM_SESSION_ID)));

                default:
                    throw new ApiException(ApiException.Type.BAD_VIEW);
            }
        } catch (CollaborationException e) {
            throw toApiException(e);
        }
    }

    @Override
    public void handleApiPersistentConnection(
            HttpMessage msg,
            HttpInputStream httpIn,
            HttpOutputStream httpOut,
            String name,
            JSONObject params)
            throws ApiException {
        if (!PCONN_SESSION_EVENTS.equals(name)) {
            throw new ApiException(ApiException.Type.BAD_PCONN);
        }

        CollaborationSession session;
        try {
            session = sessionManager.getSession(params.getString(PARAM_SESSION_ID));
        } catch (CollaborationException e) {
            throw toApiException(e);
        }

        int poll = params.optInt(PARAM_POLL, 500);
        int keepAlive = params.optInt(PARAM_KEEP_ALIVE, 30);
        EventQueueConsumer consumer = new EventQueueConsumer();
        ZAP.getEventBus()
                .registerConsumer(
                        consumer, CollaborationEventPublisher.getPublisher().getPublisherName());

        try {
            String contentType = keepAlive > 0 ? "text/plain" : "text/event-stream";
            msg.setResponseHeader(API.getDefaultResponseHeader(contentType, -1));
            msg.getResponseHeader().setHeader(HttpHeader.CONNECTION, HttpHeader._KEEP_ALIVE);
            httpOut.write(msg.getResponseHeader());

            long nextKeepAlive = System.currentTimeMillis() + keepAlive * 1000L;
            while (true) {
                Event event = consumer.poll(poll);
                if (event != null
                        && session.getId()
                                .equals(
                                        event.getParameters()
                                                .get(CollaborationEventPublisher.SESSION_ID))) {
                    httpOut.write("event: " + event.getEventType() + "\n");
                    httpOut.write("data: " + JSONObject.fromObject(event.getParameters()) + "\n\n");
                    httpOut.flush();
                }
                if (keepAlive > 0 && System.currentTimeMillis() > nextKeepAlive) {
                    httpOut.write("event: keepalive\n");
                    httpOut.write("data: {}\n\n");
                    httpOut.flush();
                    nextKeepAlive = System.currentTimeMillis() + keepAlive * 1000L;
                }
            }
        } catch (IOException e) {
            // The client closed the connection.
            LOGGER.debug("Collaboration event stream closed: {}", e.getMessage());
        } finally {
            ZAP.getEventBus().unregisterConsumer(consumer);
            httpOut.close();
            httpIn.close();
        }
    }

    private static String getMember(JSONObject params) throws ApiException {
        return ApiUtils.getNonEmptyStringParam(params, PARAM_MEMBER);
    }

    private static CollaborationRole getRole(JSONObject params) throws ApiException {
        CollaborationRole role = CollaborationRole.fromName(params.getString(PARAM_ROLE));
        if (role == null) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_ROLE);
        }
        return role;
    }

    private static FindingStatus getStatus(JSONObject params) throws ApiException {
        FindingStatus status = FindingStatus.fromName(params.getString(PARAM_STATUS));
        if (status == null) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_STATUS);
        }
        return status;
    }

    private static ApiException toApiException(CollaborationException e) {
        switch (e.getKind()) {
            case SESSION_NOT_FOUND:
            case FINDING_NOT_FOUND:
            case MEMBER_NOT_FOUND:
                return new ApiException(ApiException.Type.DOES_NOT_EXIST, e.getMessage());
            case NOT_ALLOWED:
                return new ApiException(ApiException.Type.NO_ACCESS, e.getMessage());
            case INVALID_DATA:
            default:
                return new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
        }
    }

    private static ApiResponseSet<String> getSessionResponse(CollaborationSession session) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("id", session.getId());
        fields.put("name", session.getName());
        fields.put("description", session.getDescription());
        fields.put("createdBy", session.getCreatedBy());
        fields.put("createdAt", Long.toString(session.getCreatedAt()));
        fields.put("lastModifiedAt", Long.toString(session.getLastModifiedAt()));
        fields.put("version", Long.toString(session.getVersion()));
        fields.put("memberCount", Integer.toString(session.getMemberCount()));
        fields.put("findingCount", Integer.toString(session.getFindingCount()));
        return new ApiResponseSet<>("session", fields);
    }

    private static ApiResponseSet<String> getFindingResponse(Finding finding) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("id", finding.getId());
        fields.put("name", finding.getName());
        fields.put("url", finding.getUrl());
        fields.put("param", finding.getParam());
        fields.put("risk", Integer.toString(finding.getRisk()));
        fields.put("confidence", Integer.toString(finding.getConfidence()));
        fields.put("description", finding.getDescription());
        fields.put("solution", finding.getSolution());
        fields.put("reference", finding.getReference());
        fields.put("status", finding.getStatus().name());
        fields.put("createdBy", finding.getCreatedBy());
        fields.put("createdAt", Long.toString(finding.getCreatedAt()));
        fields.put("updatedBy", finding.getUpdatedBy());
        fields.put("updatedAt", Long.toString(finding.getUpdatedAt()));
        fields.put("version", Long.toString(finding.getVersion()));
        return new ApiResponseSet<>("finding", fields);
    }

    private static ApiResponseSet<String> getAuditEntryResponse(AuditEntry entry) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("timestamp", Long.toString(entry.getTimestamp()));
        fields.put("member", entry.getMember());
        fields.put("action", entry.getAction().name());
        fields.put("detail", entry.getDetail());
        return new ApiResponseSet<>("auditEntry", fields);
    }

    private static ApiResponseSet<String> getReportResponse(CollaborationSession session) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("sessionId", session.getId());
        fields.put("name", session.getName());
        fields.put("description", session.getDescription());
        fields.put("version", Long.toString(session.getVersion()));
        for (FindingStatus status : FindingStatus.values()) {
            fields.put(
                    status.name().toLowerCase(Locale.ROOT),
                    Integer.toString(session.getFindings(status).size()));
        }
        fields.put("memberCount", Integer.toString(session.getMemberCount()));
        fields.put("findingCount", Integer.toString(session.getFindingCount()));
        return new ApiResponseSet<>("report", fields);
    }

    /** A simple queue of the events received from the event bus. */
    private static class EventQueueConsumer implements EventConsumer {

        private final BlockingQueue<Event> events = new LinkedBlockingQueue<>();

        @Override
        public void eventReceived(Event event) {
            events.offer(event);
        }

        Event poll(int timeout) {
            try {
                return events.poll(timeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }
}
