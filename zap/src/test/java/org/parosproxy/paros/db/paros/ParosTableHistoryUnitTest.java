/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.parosproxy.paros.db.paros;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.extension.option.DatabaseParam;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link ParosTableHistory}. */
class ParosTableHistoryUnitTest {

    private ParosTableHistory table;

    private Connection connection;

    @BeforeEach
    void setUp() {
        table = new ParosTableHistory();
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (connection != null) {
            connection.close();
            connection = null;
        }
    }

    @Test
    void shouldSetDatabaseOptions() {
        // Given
        DatabaseParam options = new DatabaseParam();
        // When / Then
        assertDoesNotThrow(() -> table.setDatabaseOptions(options));
    }

    @Test
    void shouldThrowWhenSettingNullDatabaseOptions() {
        // Given
        DatabaseParam options = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> table.setDatabaseOptions(options));
    }

    @Test
    void shouldReadDatabaseOptionsOnReconnect() {
        // Given
        DatabaseParam options = mock(DatabaseParam.class);
        table.setDatabaseOptions(options);
        Connection conn = mock(Connection.class);
        // When
        assertThrows(NullPointerException.class, () -> table.reconnect(conn));
        // Then
        verify(options).getRequestBodySize();
        verify(options).getResponseBodySize();
    }

    @Test
    void shouldNotReadBackTheRecordWhenWriting() throws Exception {
        // Given
        ParosTableHistory spyTable = spy(new ParosTableHistory());
        connection = HsqldbTestTables.newConnectionWithHistoryTable();
        spyTable.reconnect(connection);
        // When
        RecordHistory record = spyTable.write(1L, HistoryReference.TYPE_PROXIED, createMessage());
        // Then
        verify(spyTable, never()).read(record.getHistoryId());
    }

    @Test
    void shouldReturnTheWrittenValuesWhenWriting() throws Exception {
        // Given
        connection = HsqldbTestTables.newConnectionWithHistoryTable();
        table.reconnect(connection);
        HttpMessage message = createMessage();
        // When
        RecordHistory record = table.write(1L, HistoryReference.TYPE_PROXIED, message);
        // Then
        assertThat(record, is(not(nullValue())));
        assertThat(record.getHistoryId(), is(equalTo(1)));
        assertThat(record.getHistoryType(), is(equalTo(HistoryReference.TYPE_PROXIED)));
        assertThat(record.getSessionId(), is(equalTo(1L)));
        HttpMessage written = record.getHttpMessage();
        assertThat(
                written.getRequestHeader().getURI().toString(),
                is(equalTo("http://example.com/test")));
        assertThat(written.getRequestHeader().getMethod(), is(equalTo("GET")));
        assertThat(
                written.getRequestBody().getBytes(),
                is(equalTo("request".getBytes(StandardCharsets.US_ASCII))));
        assertThat(written.getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(
                written.getResponseBody().getBytes(),
                is(equalTo("response".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void shouldWriteRecordsThatCanBeReadBack() throws Exception {
        // Given
        connection = HsqldbTestTables.newConnectionWithHistoryTable();
        table.reconnect(connection);
        HttpMessage message = createMessage();
        // When
        RecordHistory written = table.write(1L, HistoryReference.TYPE_PROXIED, message);
        RecordHistory read = table.read(written.getHistoryId());
        // Then
        assertThat(read.getHistoryId(), is(equalTo(written.getHistoryId())));
        assertThat(read.getHistoryType(), is(equalTo(written.getHistoryType())));
        assertThat(read.getSessionId(), is(equalTo(written.getSessionId())));
        assertThat(
                read.getHttpMessage().getRequestHeader().toString(),
                is(equalTo(written.getHttpMessage().getRequestHeader().toString())));
        assertThat(
                read.getHttpMessage().getResponseHeader().toString(),
                is(equalTo(written.getHttpMessage().getResponseHeader().toString())));
        assertThat(
                read.getHttpMessage().getResponseBody().getBytes(),
                is(equalTo(written.getHttpMessage().getResponseBody().getBytes())));
    }

    @Test
    void shouldUpdateLastIndexWhenWriting() throws Exception {
        // Given
        connection = HsqldbTestTables.newConnectionWithHistoryTable();
        table.reconnect(connection);
        // When
        RecordHistory first = table.write(1L, HistoryReference.TYPE_PROXIED, createMessage());
        RecordHistory second = table.write(1L, HistoryReference.TYPE_PROXIED, createMessage());
        // Then
        assertThat(first.getHistoryId(), is(equalTo(1)));
        assertThat(second.getHistoryId(), is(equalTo(2)));
        assertThat(table.lastIndex(), is(equalTo(2)));
    }

    private static HttpMessage createMessage() throws Exception {
        HttpMessage message = new HttpMessage();
        message.getRequestHeader()
                .setMessage("GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n");
        message.getRequestBody().setBody("request");
        message.getResponseHeader().setMessage("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n");
        message.getResponseBody().setBody("response");
        return message;
    }
}
