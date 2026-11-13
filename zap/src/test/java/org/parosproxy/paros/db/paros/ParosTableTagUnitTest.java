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
import org.parosproxy.paros.db.RecordTag;

/** Unit test for {@link ParosTableTag}. */
class ParosTableTagUnitTest {

    private ParosTableTag table;

    private Connection connection;

    @BeforeEach
    void setUp() throws Exception {
        table = new ParosTableTag();
        connection = HsqldbTestTables.newConnection();
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
    void shouldNotReadBackTheRecordWhenInserting() throws Exception {
        // Given
        ParosTableTag spyTable = spy(table);
        // When
        RecordTag record = spyTable.insert(1L, "tag");
        // Then
        verify(spyTable, never()).read(record.getTagId());
    }

    @Test
    void shouldReturnTheInsertedValues() throws Exception {
        // Given / When
        RecordTag record = table.insert(1L, "tag");
        // Then
        assertThat(record, is(not(nullValue())));
        assertThat(record.getTagId(), is(equalTo(1L)));
        assertThat(record.getHistoryId(), is(equalTo(1L)));
        assertThat(record.getTag(), is(equalTo("tag")));
    }

    @Test
    void shouldInsertTagsThatCanBeReadBack() throws Exception {
        // Given
        RecordTag inserted = table.insert(1L, "tag");
        // When
        List<RecordTag> tags = table.getTagsForHistoryID(1L);
        // Then
        assertThat(tags.size(), is(equalTo(1)));
        assertThat(tags.get(0).getTagId(), is(equalTo(inserted.getTagId())));
        assertThat(tags.get(0).getTag(), is(equalTo("tag")));
    }

    @Test
    void shouldAssignIncrementingTagIds() throws Exception {
        // Given / When
        RecordTag first = table.insert(1L, "tag1");
        RecordTag second = table.insert(2L, "tag2");
        // Then
        assertThat(first.getTagId(), is(equalTo(1L)));
        assertThat(second.getTagId(), is(equalTo(2L)));
    }
}
