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
package org.zaproxy.zap.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

/** Test for the release instructions in {@code RELEASING.md}. */
class ReleasingDocUnitTest {

    private static final String RELEASING_DOC_NAME = "RELEASING.md";

    @Test
    void shouldLinkToTheCurrentLinuxReposPackage() throws IOException {
        // Given
        Path releasingDoc = findReleasingDoc();
        assumeTrue(
                releasingDoc != null,
                "Test requires the " + RELEASING_DOC_NAME + " file, not available in this build.");
        String contents = Files.readString(releasingDoc, StandardCharsets.UTF_8);
        // When / Then
        assertThat(
                contents,
                containsString(
                        "https://software.opensuse.org/download.html?project=home%3Acabelo&package=zap"));
        // The OBS package was renamed from owasp-zap to zap, the old name is no longer published,
        // so linking to it would not update the package used by the Linux distributions.
        assertThat(contents, not(containsString("package=owasp-zap")));
    }

    private static Path findReleasingDoc() {
        for (Path dir = Paths.get("").toAbsolutePath(); dir != null; dir = dir.getParent()) {
            Path candidate = dir.resolve(RELEASING_DOC_NAME);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        return null;
    }
}
