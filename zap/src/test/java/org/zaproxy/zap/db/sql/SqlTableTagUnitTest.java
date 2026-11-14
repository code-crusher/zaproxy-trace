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
package org.zaproxy.zap.db.sql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.DbUtils;

/**
 * Unit test for the SQL of the TAG table used by {@link SqlTableTag}.
 *
 * <p>Verifies that the TAG table has an index on HISTORYID, which is required for acceptable
 * performance of the lookups done while passively scanning (issue 9278). The SQL statements are
 * those from the {@code db/hsqldb.properties} file, executed against a real (in-memory) database.
 */
class SqlTableTagUnitTest {

    private static final String INDEX_NAME = "TAG_HISTORYID_INDEX";

    private Properties sqlProperties;
    private Connection connection;

    @BeforeEach
    void setUp() throws Exception {
        sqlProperties = new Properties();
        try (InputStream in = getSQLProperties("/db/hsqldb.properties")) {
            sqlProperties.load(in);
        }

        connection = DriverManager.getConnection("jdbc:hsqldb:mem:SqlTableTagUnitTest", "sa", "");
    }

    private static InputStream getSQLProperties(String path) throws IOException {
        InputStream in = SqlTableTagUnitTest.class.getResourceAsStream(path);
        assertNotNull(in, "The SQL properties file should exist: " + path);
        return in;
    }

    @AfterEach
    void tearDown() throws Exception {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DROP TABLE TAG IF EXISTS");
        }
        connection.close();
    }

    @Test
    void shouldHaveIndexSQLStatement() {
        // Given / When
        String sql = sqlProperties.getProperty("tag.ps.indexhistoryid");
        // Then
        assertNotNull(sql, "The SQL to create the TAG index should be defined.");
        assertTrue(sql.toUpperCase().contains("HISTORYID"), "The index should be on HISTORYID.");
    }

    @Test
    void shouldCreateIndexOnHistoryIdWithSQLStatements() throws Exception {
        // Given a TAG table created with the SQL from the properties file
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sqlProperties.getProperty("tag.ps.createtable"));
        }
        assertFalse(DbUtils.hasIndex(connection, "TAG", INDEX_NAME));
        // When
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sqlProperties.getProperty("tag.ps.indexhistoryid"));
        }
        // Then
        assertTrue(
                DbUtils.hasIndex(connection, "TAG", INDEX_NAME),
                "The TAG table should have the index " + INDEX_NAME);
    }

    @Test
    void shouldInsertAndReadTagsWithSQLStatements() throws Exception {
        // Given
        createTableAndIndex();
        String insert = sqlProperties.getProperty("tag.ps.insert");
        String getTags = sqlProperties.getProperty("tag.ps.gettagsforhid");
        // When
        try (java.sql.PreparedStatement psInsert = connection.prepareStatement(insert)) {
            psInsert.setLong(1, 1);
            psInsert.setString(2, "Form");
            psInsert.executeUpdate();
        }
        int count = 0;
        try (java.sql.PreparedStatement psGetTags = connection.prepareStatement(getTags)) {
            psGetTags.setLong(1, 1);
            try (ResultSet rs = psGetTags.executeQuery()) {
                while (rs.next()) {
                    assertEquals("Form", rs.getString("TAG"));
                    count++;
                }
            }
        }
        // Then
        assertEquals(1, count);
    }

    private void createTableAndIndex() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sqlProperties.getProperty("tag.ps.createtable"));
            stmt.execute(sqlProperties.getProperty("tag.ps.indexhistoryid"));
        }
    }
}
