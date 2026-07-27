"""Detection tests for four more policy gates (bd imperialism-decomp-x1cl).

Third batch, same discipline: positive detection tests, because the failure mode this
bead is about is a regex silently ceasing to match while the gate keeps exiting 0.

Takes the covered set from 8 of 18 to 12 of 18.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.workflow.check_boundary_ratchet import INLINE_FN_PTR_CAST_RE
from tools.workflow.check_global_location import find_global_markers
from tools.workflow.check_synthetic_names import (
    COMMENT_LINE_RE,
    SYNTHETIC_MARKER_RE,
    canonical_addr,
)
from tools.workflow.check_tooling_surface import JUST_MODULE_RE, PIPE_SPLIT_RE, module_exists


class SyntheticNameTest(unittest.TestCase):
    """Construction Hard Rule 10: a SYNTHETIC claim needs an exact backtick name."""

    def test_marker_is_matched_and_addresses_canonicalize(self) -> None:
        match = SYNTHETIC_MARKER_RE.match("// SYNTHETIC: IMPERIALISM 0x0049c3b0")
        assert match is not None
        self.assertEqual(match.group("module"), "IMPERIALISM")
        self.assertEqual(canonical_addr(match.group("offset")), canonical_addr("0x49c3b0"))

    def test_a_function_marker_is_not_a_synthetic_marker(self) -> None:
        self.assertIsNone(SYNTHETIC_MARKER_RE.match("// FUNCTION: IMPERIALISM 0x0049c3b0"))

    def test_backtick_scalar_deleting_name_is_captured_verbatim(self) -> None:
        # The name must match the inventory row EXACTLY, backticks and trailing
        # apostrophe included, or the address never pairs.
        line = "// TCity::`scalar deleting destructor'"
        match = COMMENT_LINE_RE.match(line)
        assert match is not None
        self.assertEqual(match.group("name"), "TCity::`scalar deleting destructor'")

    def test_trailing_whitespace_does_not_change_the_name(self) -> None:
        match = COMMENT_LINE_RE.match("//  WaveLoadDescriptor::~WaveLoadDescriptor   \n")
        assert match is not None
        self.assertEqual(match.group("name"), "WaveLoadDescriptor::~WaveLoadDescriptor")


class GlobalLocationTest(unittest.TestCase):
    """GLOBAL markers belong in global_data_tables.cpp and nowhere else."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _write(self, name: str, source: str) -> None:
        (self.root / name).write_text(source, encoding="utf-8")

    def test_global_marker_outside_the_allowed_file_is_flagged(self) -> None:
        self._write("TCity.cpp", "// GLOBAL: IMPERIALISM 0x006a43d4\nTCity* g_pCity;\n")
        violations = find_global_markers(self.root)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0][1], 1)

    def test_the_allowed_file_is_excluded(self) -> None:
        self._write(
            "global_data_tables.cpp", "// GLOBAL: IMPERIALISM 0x006a43d4\nTCity* g_pCity;\n"
        )
        self.assertEqual(find_global_markers(self.root), [])

    def test_a_function_marker_is_not_a_global_marker(self) -> None:
        self._write("TCity.cpp", "// FUNCTION: IMPERIALISM 0x004b3b20\nvoid f() {}\n")
        self.assertEqual(find_global_markers(self.root), [])


class BoundaryRatchetTest(unittest.TestCase):
    """The function-pointer cast ban: the durable fix is a real method, not a cast."""

    def test_inline_function_pointer_casts_are_matched_in_every_convention(self) -> None:
        for source in (
            "auto fn = reinterpret_cast<void (__thiscall*)(void*)>(addr);",
            "auto fn = reinterpret_cast<int (__fastcall*)(void*, int)>(addr);",
            "auto fn = reinterpret_cast<void (__cdecl*)(void)>(addr);",
            "auto fn = reinterpret_cast<void (*)(void)>(addr);",
        ):
            with self.subTest(source=source):
                self.assertIsNotNone(INLINE_FN_PTR_CAST_RE.search(source))

    def test_an_ordinary_pointer_cast_is_not_a_function_pointer_cast(self) -> None:
        # Pointer-to-pointer casts are codegen-neutral and explicitly allowed; only
        # function-pointer casts are the boundary defect.
        self.assertIsNone(INLINE_FN_PTR_CAST_RE.search("auto* p = reinterpret_cast<TCity*>(raw);"))


class ToolingSurfaceTest(unittest.TestCase):
    """Every module a just recipe runs must exist and be listed in the manifest."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_module_invocations_are_extracted_from_a_recipe(self) -> None:
        self.assertEqual(
            JUST_MODULE_RE.findall("  uv run python -m tools.workflow.check_repo_hygiene\n"),
            ["tools.workflow.check_repo_hygiene"],
        )

    def test_a_module_file_and_a_package_both_count_as_existing(self) -> None:
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "__init__.py").write_text("")
        (self.root / "pkg" / "mod.py").write_text("")
        self.assertTrue(module_exists(self.root, "pkg.mod"))
        self.assertTrue(module_exists(self.root, "pkg"))

    def test_a_missing_module_is_reported_as_absent(self) -> None:
        self.assertFalse(module_exists(self.root, "pkg.nope"))

    def test_a_directory_without_init_is_not_a_package(self) -> None:
        (self.root / "bare").mkdir()
        self.assertFalse(module_exists(self.root, "bare"))

    def test_naive_pipe_splitting_is_detected(self) -> None:
        # The inventory is pipe-delimited but quoted fields exist; a bare .split("|")
        # silently corrupts rows, so the gate bans it in favour of the csv reader.
        self.assertIsNotNone(PIPE_SPLIT_RE.search('parts = line.split("|")'))
        self.assertIsNotNone(PIPE_SPLIT_RE.search("parts = line.split('|')"))

    def test_splitting_on_another_delimiter_is_not_flagged(self) -> None:
        self.assertIsNone(PIPE_SPLIT_RE.search('parts = line.split(",")'))


if __name__ == "__main__":
    unittest.main()
