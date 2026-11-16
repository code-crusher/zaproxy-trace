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
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.WithConfigsTest;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;

/** Unit test for {@link CollaborationAPI}. */
class CollaborationAPIUnitTest extends WithConfigsTest {

    private static final String ALICE = "alice";
    private static final String BOB = "bob";

    private AtomicLong clock;
    private List<Event> events;
    private CollaborationSessionManager manager;
    private CollaborationAPI api;

    @BeforeEach
    void setUp() {
        WithConfigsTest.setUpConstantMessages();
        clock = new AtomicLong(1000);
        events = new ArrayList<>();
        manager =
                new CollaborationSessionManager(
                        new InMemoryCollaborationSessionStore(), events::add, clock::get);
        api = new CollaborationAPI(manager);
    }

    @Test
    void shouldHavePrefix() {
        assertThat(api.getPrefix(), is(equalTo("collaboration")));
    }

    @Test
    void shouldCreateSession() throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("name", "Engagement");
        params.put("member", ALICE);
        // When
        ApiResponse response = api.handleApiAction("createSession", params);
        // Then
        assertThat(response, is(instanceOf(ApiResponseSet.class)));
        assertThat(response.getName(), is(equalTo("session")));
        JSONObject json = (JSONObject) response.toJSON();
        assertThat(json.getString("id"), is(equalTo(manager.getSessions().get(0).getId())));
        assertThat(json.getString("name"), is(equalTo("Engagement")));
        assertThat(json.getString("createdBy"), is(equalTo(ALICE)));
        assertThat(json.getString("createdAt"), is(equalTo("1000")));
        assertThat(json.getString("version"), is(equalTo("2")));
        assertThat(json.getString("memberCount"), is(equalTo("1")));
        assertThat(json.getString("findingCount"), is(equalTo("0")));
    }

    @Test
    void shouldRequireNameToCreateSession() {
        // Given
        ApiAction action = null;
        for (ApiAction apiAction : api.getApiActions()) {
            if ("createSession".equals(apiAction.getName())) {
                action = apiAction;
            }
        }
        // Then
        assertThat(action, is(notNullValue()));
        assertThat(action.getMandatoryParamNames(), contains("name"));
    }

    @Test
    void shouldGetSessions() throws Exception {
        // Given
        manager.createSession("One", "", ALICE);
        manager.createSession("Two", "", ALICE);
        // When
        ApiResponse response = api.handleApiView("getSessions", new JSONObject());
        // Then
        assertThat(response, is(instanceOf(ApiResponseList.class)));
        assertThat(((ApiResponseList) response).getItems(), hasSize(2));
    }

    @Test
    void shouldGetSession() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        // When
        ApiResponse response = api.handleApiView("getSession", params);
        // Then
        assertThat(response.getName(), is(equalTo("session")));
    }

    @Test
    void shouldFailToGetUnknownSession() {
        // Given
        JSONObject params = new JSONObject();
        params.put("sessionId", "unknown");
        // When
        ApiException e =
                assertThrows(ApiException.class, () -> api.handleApiView("getSession", params));
        // Then
        assertThat(e.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
    }

    @Test
    void shouldJoinSession() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("member", BOB);
        params.put("role", "reviewer");
        // When
        api.handleApiAction("joinSession", params);
        // Then
        assertThat(session.getRole(BOB), is(equalTo(CollaborationRole.REVIEWER)));
    }

    @Test
    void shouldFailToJoinWithUnknownRole() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("member", BOB);
        params.put("role", "unknown");
        // When
        ApiException e =
                assertThrows(ApiException.class, () -> api.handleApiAction("joinSession", params));
        // Then
        assertThat(e.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
    }

    @Test
    void shouldShareFinding() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("member", ALICE);
        params.put("name", "SQL Injection");
        params.put("url", "https://example.com/login");
        params.put("param", "user");
        params.put("risk", Alert.RISK_HIGH);
        params.put("confidence", Alert.CONFIDENCE_HIGH);
        params.put("description", "desc");
        params.put("solution", "solution");
        params.put("reference", "reference");
        // When
        ApiResponse response = api.handleApiAction("shareFinding", params);
        // Then
        assertThat(response.getName(), is(equalTo("finding")));
        assertThat(session.getFindings(), hasSize(1));
    }

    @Test
    void shouldGetFindingsFilteredByStatus() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.REVIEWER);
        Finding finding =
                manager.shareFinding(
                        session.getId(), ALICE, "XSS", "https://example.com", "", 1, 1, "", "", "");
        manager.updateFinding(session.getId(), BOB, finding.getId(), FindingStatus.CONFIRMED);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("status", "confirmed");
        // When
        ApiResponse response = api.handleApiView("getFindings", params);
        // Then
        assertThat(((ApiResponseList) response).getItems(), hasSize(1));
    }

    @Test
    void shouldFailToGetFindingsWithUnknownStatus() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("status", "unknown");
        // When
        ApiException e =
                assertThrows(ApiException.class, () -> api.handleApiView("getFindings", params));
        // Then
        assertThat(e.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
    }

    @Test
    void shouldGetAuditTrail() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        // When
        ApiResponse response = api.handleApiView("getAuditTrail", params);
        // Then
        assertThat(response.getName(), is(equalTo("getAuditTrail")));
        assertThat(((ApiResponseList) response).getItems(), hasSize(1));
    }

    @Test
    void shouldGetReport() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.shareFinding(
                session.getId(), ALICE, "XSS", "https://example.com", "", 1, 1, "", "", "");
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        // When
        ApiResponse response = api.handleApiView("getReport", params);
        // Then
        assertThat(response.getName(), is(equalTo("report")));
        assertThat(
                ((ApiResponseSet<?>) response).toJSON().toString(),
                is(
                        equalTo(
                                "{\"sessionId\":\""
                                        + session.getId()
                                        + "\",\"name\":\"Engagement\",\"description\":\"\",\"version\":\"3\",\"open\":\"1\",\"confirmed\":\"0\",\"false_positive\":\"0\",\"memberCount\":\"1\",\"findingCount\":\"1\"}")));
    }

    @Test
    void shouldFailToShareFindingWhenNotAllowed() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.REPORTER);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("member", BOB);
        params.put("name", "XSS");
        params.put("url", "https://example.com");
        // When
        ApiException e =
                assertThrows(ApiException.class, () -> api.handleApiAction("shareFinding", params));
        // Then
        assertThat(e.getType(), is(equalTo(ApiException.Type.NO_ACCESS)));
    }

    @Test
    void shouldFailToUpdateFindingWhenNotAllowed() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        Finding finding =
                manager.shareFinding(
                        session.getId(), ALICE, "XSS", "https://example.com", "", 1, 1, "", "", "");
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("member", ALICE);
        params.put("findingId", finding.getId());
        params.put("status", "confirmed");
        // When
        ApiException e =
                assertThrows(
                        ApiException.class, () -> api.handleApiAction("updateFinding", params));
        // Then
        assertThat(e.getType(), is(equalTo(ApiException.Type.NO_ACCESS)));
    }

    @Test
    void shouldFailToUpdateUnknownFinding() throws Exception {
        // Given
        CollaborationSession session = manager.createSession("Engagement", "", ALICE);
        manager.joinSession(session.getId(), BOB, CollaborationRole.REVIEWER);
        JSONObject params = new JSONObject();
        params.put("sessionId", session.getId());
        params.put("member", BOB);
        params.put("findingId", "unknown");
        params.put("status", "confirmed");
        // When
        ApiException e =
                assertThrows(
                        ApiException.class, () -> api.handleApiAction("updateFinding", params));
        // Then
        assertThat(e.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
    }

    @Test
    void shouldRegisterSessionEventsPersistentConnection() {
        assertThat(
                api.getApiPersistentConnections(),
                contains(org.hamcrest.Matchers.hasProperty("name", is(equalTo("sessionEvents")))));
    }

    @Test
    void shouldFailToHandleUnknownAction() {
        ApiException e =
                assertThrows(
                        ApiException.class, () -> api.handleApiAction("unknown", new JSONObject()));
        assertThat(e.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @Test
    void shouldFailToHandleUnknownView() {
        ApiException e =
                assertThrows(
                        ApiException.class, () -> api.handleApiView("unknown", new JSONObject()));
        assertThat(e.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldFailToHandleUnknownPersistentConnection() {
        ApiException e =
                assertThrows(
                        ApiException.class,
                        () ->
                                api.handleApiPersistentConnection(
                                        mock(org.parosproxy.paros.network.HttpMessage.class),
                                        null,
                                        null,
                                        "unknown",
                                        new JSONObject()));
        assertThat(e.getType(), is(equalTo(ApiException.Type.BAD_PCONN)));
    }
}
