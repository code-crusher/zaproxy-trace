"""Tests for the Dockerfiles."""

import os
import re
import unittest
from glob import glob


DOCKER_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

# Base Debian releases that are (or will be) EOL, the images must not use them.
DEPRECATED_DEBIAN_BASES = ["bullseye", "bookworm"]

# Debian releases that are currently supported.
SUPPORTED_DEBIAN_BASES = ["trixie"]

DOCKERFILES = sorted(glob(os.path.join(DOCKER_DIR, "Dockerfile*")))


def read_dockerfiles():
    dockerfiles = {}
    for path in DOCKERFILES:
        with open(path, "r", encoding="utf-8") as file:
            dockerfiles[os.path.basename(path)] = file.read()
    return dockerfiles


class TestDockerfiles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dockerfiles = read_dockerfiles()

    def test_dockerfiles_found(self):
        """The Dockerfiles should be found."""
        self.assertGreaterEqual(len(self.dockerfiles), 5)

    def test_no_deprecated_debian_base(self):
        """The Dockerfiles should not use EOL Debian releases (Issue 9310)."""
        for name, content in self.dockerfiles.items():
            with self.subTest(dockerfile=name):
                for base in DEPRECATED_DEBIAN_BASES:
                    self.assertNotRegex(content, "debian:{}-slim".format(base))

    def test_debian_bases_supported(self):
        """The Debian bases used should be supported releases."""
        for name, content in self.dockerfiles.items():
            with self.subTest(dockerfile=name):
                for match in re.findall(r"debian:([a-z]+)-slim", content):
                    self.assertIn(match, SUPPORTED_DEBIAN_BASES)

    def test_jdk_consistency(self):
        """The JDK used should be available in the Debian base."""
        for name, content in self.dockerfiles.items():
            with self.subTest(dockerfile=name):
                if "debian:trixie-slim" not in content:
                    continue
                self.assertNotIn("openjdk-17-jdk", content)
                self.assertNotIn("java-17-openjdk", content)

    def test_java_home_matches_jdk(self):
        """The JAVA_HOME should match the installed OpenJDK."""
        jdk_home = re.compile(r"ENV JAVA_HOME=/usr/lib/jvm/java-(\d+)-openjdk")
        for name, content in self.dockerfiles.items():
            with self.subTest(dockerfile=name):
                jdk_installed = set(re.findall(r"openjdk-(\d+)-jdk", content))
                jdk_homes = set(jdk_home.findall(content))
                if jdk_homes:
                    self.assertEqual(jdk_installed, jdk_homes)
