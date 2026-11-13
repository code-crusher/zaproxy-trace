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
package org.parosproxy.paros.db.paros;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.sql.Connection;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.RecordAlert;

/** Unit test for {@link ParosTableAlert}. */
class ParosTableAlertUnitTest {

    private ParosTableAlert table;

    private Connection connection;

    @BeforeEach
    void setUp() throws Exception {
        table = new ParosTableAlert();
        connection = HsqldbTestTables.newConnectionWithAlertTable();
        table.reconnect(connection);
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (connection != null) {
            connection.close();
            connection = null;
        }
    }

    @Test
    void shouldNotReadBackTheRecordWhenWriting() throws Exception {
        // Given
        ParosTableAlert spyTable = spy(table);
        // When
        RecordAlert record = write(spyTable);
        // Then
        verify(spyTable, never()).read(record.getAlertId());
    }

    @Test
    void shouldReturnTheWrittenValues() throws Exception {
        // Given / When
        RecordAlert record = write(table);
        // Then
        assertThat(record, is(not(nullValue())));
        assertThat(record.getAlertId(), is(equalTo(0)));
        assertThat(record.getScanId(), is(equalTo(1)));
        assertThat(record.getPluginId(), is(equalTo(2)));
        assertThat(record.getAlert(), is(equalTo("Alert")));
        assertThat(record.getRisk(), is(equalTo(3)));
        assertThat(record.getConfidence(), is(equalTo(2)));
        assertThat(record.getDescription(), is(equalTo("Description")));
        assertThat(record.getUri(), is(equalTo("http://example.com/")));
        assertThat(record.getParam(), is(equalTo("param")));
        assertThat(record.getAttack(), is(equalTo("attack")));
        assertThat(record.getOtherInfo(), is(equalTo("Other info")));
        assertThat(record.getSolution(), is(equalTo("Solution")));
        assertThat(record.getReference(), is(equalTo("Reference")));
        assertThat(record.getEvidence(), is(equalTo("Evidence")));
        assertThat(record.getCweId(), is(equalTo(1)));
        assertThat(record.getWascId(), is(equalTo(2)));
        assertThat(record.getHistoryId(), is(equalTo(3)));
        assertThat(record.getSourceHistoryId(), is(equalTo(4)));
        assertThat(record.getSourceId(), is(equalTo(5)));
        assertThat(record.getAlertRef(), is(equalTo("6-1")));
        assertThat(record.getInputVector(), is(equalTo("Input vector")));
        assertThat(record.getNodeName(), is(equalTo("Node name")));
    }

    @Test
    void shouldWriteAlertsThatCanBeReadBack() throws Exception {
        // Given
        RecordAlert written = write(table);
        // When
        List<RecordAlert> alerts = table.getAlertsBySourceHistoryId(4);
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(alerts.get(0).getAlertId(), is(equalTo(written.getAlertId())));
        assertThat(alerts.get(0).getAlert(), is(equalTo("Alert")));
        assertThat(alerts.get(0).getUri(), is(equalTo("http://example.com/")));
    }

    private static RecordAlert write(ParosTableAlert table) throws Exception {
        return table.write(
                1,
                2,
                "Alert",
                3,
                2,
                "Description",
                "http://example.com/",
                "param",
                "attack",
                "Other info",
                "Solution",
                "Reference",
                "Evidence",
                1,
                2,
                3,
                4,
                5,
                "6-1",
                "Input vector",
                "Node name");
    }
}
