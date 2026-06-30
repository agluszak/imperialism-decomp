#!/usr/bin/env python3
"""Tests for tools.common.pipe_csv."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.common.pipe_csv import normalize_hex, read_pipe_rows, read_pipe_table, read_pipe_map


class NormalizeHexTests(unittest.TestCase):
    def test_strips_prefix_and_lowercases(self) -> None:
        self.assertEqual(normalize_hex("0x004E73F0"), "004e73f0")

    def test_no_prefix(self) -> None:
        self.assertEqual(normalize_hex("004E73F0"), "004e73f0")

    def test_whitespace_stripped(self) -> None:
        self.assertEqual(normalize_hex("  0x00FF  "), "00ff")

    def test_already_normalized(self) -> None:
        self.assertEqual(normalize_hex("abcd"), "abcd")


class ReadPipeRowsTests(unittest.TestCase):
    def test_reads_pipe_delimited(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("address|name|note\n")
            f.write("0x004E73F0|Foo|some note\n")
            f.write("0x00500000|Bar|\n")
            path = Path(f.name)

        rows = read_pipe_rows(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["address"], "0x004E73F0")
        self.assertEqual(rows[0]["name"], "Foo")
        self.assertEqual(rows[0]["note"], "some note")
        self.assertEqual(rows[1]["name"], "Bar")
        self.assertEqual(rows[1]["note"], "")
        path.unlink()

    def test_empty_file_returns_empty(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("col1|col2\n")
            path = Path(f.name)
        rows = read_pipe_rows(path)
        self.assertEqual(rows, [])
        path.unlink()


class ReadPipeTableTests(unittest.TestCase):
    def test_returns_fieldnames_and_rows(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("address|name\n")
            f.write("0x100|Alpha\n")
            path = Path(f.name)

        fieldnames, rows = read_pipe_table(path)
        self.assertEqual(fieldnames, ["address", "name"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["address"], "0x100")
        path.unlink()


class ReadPipeMapTests(unittest.TestCase):
    def test_builds_key_value_map(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("key|value\n")
            f.write("alpha|one\n")
            f.write("beta|two\n")
            path = Path(f.name)

        result = read_pipe_map(path, "key", "value")
        self.assertEqual(result, {"alpha": "one", "beta": "two"})
        path.unlink()

    def test_normalizes_keys_and_values(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("key|value\n")
            f.write("0x00FF|HELLO\n")
            path = Path(f.name)

        result = read_pipe_map(
            path, "key", "value",
            normalize_key=str.lower,
            normalize_value=str.lower,
        )
        self.assertEqual(result, {"0x00ff": "hello"})
        path.unlink()

    def test_missing_file_returns_empty(self) -> None:
        result = read_pipe_map(Path("/nonexistent/file.csv"), "key", "value")
        self.assertEqual(result, {})

    def test_skips_empty_keys(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("key|value\n")
            f.write("|hello\n")
            f.write("alpha|world\n")
            path = Path(f.name)

        result = read_pipe_map(path, "key", "value")
        self.assertEqual(result, {"alpha": "world"})
        path.unlink()


if __name__ == "__main__":
    unittest.main()
