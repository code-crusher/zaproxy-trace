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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.paros.ParosDatabase;
import org.zaproxy.zap.WithConfigsTest;

/**
 * Unit test for {@link Model}.
 *
 * <p>Verifies that the database connection is restored when persisting or snapshotting the session
 * fails, for example, if HSQLDB fails to open the copied database (Issue 9445).
 */
class ModelUnitTest extends WithConfigsTest {

    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    @TempDir Path sessionDir;

    private ParosDatabase database;
    private Model modelUnderTest;
    private String currentDbName;

    @BeforeEach
    void setUp() throws Exception {
        database = new ParosDatabase();
        database.setDatabaseOptions(super.model.getOptionsParam().getDatabaseParam());
        modelUnderTest = createModel();

        currentDbName = dbFile("untitled1");
        createDb(currentDbName);
        insertHistoryRows(currentDbName, 1);
        database.open(currentDbName);
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (database != null) {
            database.close(false, false);
        }
    }

    @Test
    void shouldCopySessionDb() throws Exception {
        // Given
        String destFile = dbFile("copied");
        // When
        modelUnderTest.copySessionDb(currentDbName, destFile);
        // Then
        assertDbUsable();
        assertThat(database.getTableHistory().getHistoryIds(1).size(), is(1));
    }

    @Test
    void shouldRestoreDbConnectionWhenCopiedSessionDbCannotBeOpened() throws Exception {
        // Given
        String destFile = dbFile("corrupted");
        ParosDatabase spiedDatabase = spyDatabase();
        Exception openFailure = new Exception("IO error: RowInputBinary");
        doThrow(openFailure).when(spiedDatabase).open(destFile);
        // When
        Exception exception =
                assertThrows(
                        Exception.class,
                        () -> modelUnderTest.copySessionDb(currentDbName, destFile));
        // Then
        assertThat(exception, is(openFailure));
        assertDbUsable();
    }

    @Test
    void shouldRestoreDbConnectionWhenSessionDbCannotBeCopied() throws Exception {
        // Given
        String destFile = dbFile("not-writable");
        // A directory in place of the .data file causes the copy of the DB files to fail.
        Files.createDirectories(Path.of(destFile + ".data"));
        // When
        assertThrows(Exception.class, () -> modelUnderTest.copySessionDb(currentDbName, destFile));
        // Then
        assertDbUsable();
    }

    @Test
    void shouldSnapshotSessionDb() throws Exception {
        // Given
        String destFile = dbFile("snapshotted");
        // When
        modelUnderTest.snapshotSessionDb(currentDbName, destFile);
        // Then
        assertDbUsable();
        assertThat(database.getTableHistory().getHistoryIds(1).size(), is(1));
    }

    @Test
    void shouldRestoreDbConnectionWhenSnapshotDbCannotBeCopied() throws Exception {
        // Given
        String destFile = dbFile("snapshot-not-writable");
        // A directory in place of the .data file causes the copy of the DB files to fail.
        Files.createDirectories(Path.of(destFile + ".data"));
        // When
        assertThrows(
                Exception.class, () -> modelUnderTest.snapshotSessionDb(currentDbName, destFile));
        // Then
        assertDbUsable();
    }

    private Model createModel() {
        return new Model() {
            @Override
            public Database getDb() {
                return database;
            }
        };
    }

    private ParosDatabase spyDatabase() {
        database = spy(database);
        modelUnderTest = createModel();
        return database;
    }

    private String dbFile(String name) {
        return new File(sessionDir.toFile(), name).getAbsolutePath();
    }

    private void assertDbUsable() throws Exception {
        // Reads/writes should not throw, the connection to the current DB must have been restored.
        database.getTableSession().update(1, "Session");
        assertThat(database.getTableHistory().getHistoryIds(1).size(), is(1));
    }

    private static void createDb(String path) throws Exception {
        // Copy the bundled DB template, just like Model.createAndOpenUntitledDb() does.
        try (var is = Model.class.getResourceAsStream("/org/zaproxy/zap/resources/zapdb.script")) {
            Files.copy(is, Path.of(path + ".script"));
        }
    }

    private static void insertHistoryRows(String path, int count) throws Exception {
        try (Connection conn = getConnection(path);
                Statement stmt = conn.createStatement()) {
            for (int i = 0; i < count; i++) {
                stmt.execute(
                        "INSERT INTO HISTORY (SESSIONID, HISTTYPE, URI) VALUES (1, 1, 'http://t/"
                                + i
                                + "')");
            }
        }
    }

    private static Connection getConnection(String path) throws SQLException {
        return DriverManager.getConnection(
                "jdbc:hsqldb:file:" + path.replace('\\', '/'), DB_USER, DB_PASSWORD);
    }
}
