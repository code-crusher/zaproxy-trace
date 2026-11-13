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
package org.parosproxy.paros.model;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.db.TableTag;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link HistoryReference}. */
class HistoryReferenceUnitTest {

    private TableHistory tableHistory;
    private TableTag tableTag;
    private TableAlert tableAlert;

    private Session session;
    private HttpMessage message;

    @BeforeEach
    void setUp() throws Exception {
        tableHistory = mock(TableHistory.class);
        tableTag = mock(TableTag.class);
        tableAlert = mock(TableAlert.class);
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableTag(tableTag);
        HistoryReference.setTableAlert(tableAlert);

        session = mock(Session.class);
        given(session.getSessionId()).willReturn(1L);

        message = new HttpMessage();
        message.getRequestHeader()
                .setMessage("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        message.getResponseHeader().setMessage("HTTP/1.1 200 OK\r\n\r\n");

        RecordHistory recordHistory = mock(RecordHistory.class);
        given(recordHistory.getHistoryId()).willReturn(1);
        given(recordHistory.getHistoryType()).willReturn(HistoryReference.TYPE_PROXIED);
        given(recordHistory.getSessionId()).willReturn(1L);
        given(recordHistory.getHttpMessage()).willReturn(message);
        given(tableHistory.write(anyLong(), anyInt(), any(HttpMessage.class)))
                .willReturn(recordHistory);
    }

    @AfterEach
    void cleanUp() {
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableTag(null);
        HistoryReference.setTableAlert(null);
    }

    @Test
    void shouldNotQueryTagsWhenCreatingFromNewMessage() throws Exception {
        // Given / When
        new HistoryReference(session, HistoryReference.TYPE_PROXIED, message);
        // Then
        verify(tableTag, never()).getTagsForHistoryID(anyLong());
    }

    @Test
    void shouldNotQueryAlertsWhenCreatingFromNewMessage() throws Exception {
        // Given / When
        new HistoryReference(session, HistoryReference.TYPE_PROXIED, message);
        // Then
        verify(tableAlert, never()).getAlertsBySourceHistoryId(anyInt());
    }

    @Test
    void shouldHaveNoTagsWhenCreatingFromNewMessage() throws Exception {
        // Given / When
        HistoryReference reference =
                new HistoryReference(session, HistoryReference.TYPE_PROXIED, message);
        // Then
        assertThat(reference.getTags(), is(empty()));
    }

    @Test
    void shouldHaveNoAlertsWhenCreatingFromNewMessage() throws Exception {
        // Given / When
        HistoryReference reference =
                new HistoryReference(session, HistoryReference.TYPE_PROXIED, message);
        // Then
        assertThat(reference.hasAlerts(), is(equalTo(false)));
        assertThat(reference.getAlerts(), is(empty()));
    }

    @Test
    void shouldWriteTheMessageWhenCreatingFromNewMessage() throws Exception {
        // Given / When
        HistoryReference reference =
                new HistoryReference(session, HistoryReference.TYPE_PROXIED, message);
        // Then
        verify(tableHistory).write(eq(1L), eq(HistoryReference.TYPE_PROXIED), eq(message));
        assertThat(reference.getHistoryId(), is(equalTo(1)));
    }
}
