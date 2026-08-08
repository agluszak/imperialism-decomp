from pathlib import Path
import tempfile
import unittest

from tools.workflow.rewrite_return_types import apply_replacements, plan_replacements


def _repo(tmp_path: Path, header_decl: str = "  virtual char IsReady(int value);\n") -> Path:
    (tmp_path / "include/game").mkdir(parents=True)
    (tmp_path / "src/game").mkdir(parents=True)
    (tmp_path / "include/game/TThing.h").write_text(
        "class TThing {\npublic:\n" + header_decl + "};\n", encoding="utf-8")
    (tmp_path / "src/game/TThing.cpp").write_text(
        "// FUNCTION: IMPERIALISM 0x00401000\n"
        "char TThing::IsReady(int value) {\n"
        "  return value != 0;\n"
        "}\n",
        encoding="utf-8")
    return tmp_path


class RewriteReturnTypesTests(unittest.TestCase):
    def test_plans_and_applies_declaration_and_definition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _repo(Path(directory))
            replacements = plan_replacements(
                repo, [0x00401000], old_type="char", new_type="bool")

            self.assertEqual(
                [item.role for item in replacements], ["definition", "declaration"])
            apply_replacements(replacements)

            self.assertIn(
                "virtual bool IsReady(int value);",
                (repo / "include/game/TThing.h").read_text())
            self.assertIn(
                "bool TThing::IsReady(int value)",
                (repo / "src/game/TThing.cpp").read_text())

    def test_rejects_stale_or_ambiguous_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _repo(
                Path(directory),
                "  char IsReady(int value);\n  char IsReady(short value);\n")

            with self.assertRaisesRegex(
                    ValueError, "expected one char declaration.*found 2"):
                plan_replacements(
                    repo, [0x00401000], old_type="char", new_type="bool")

    def test_rejects_plan_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = _repo(Path(directory), "  bool IsReady(int value);\n")
            original = (repo / "src/game/TThing.cpp").read_text()

            with self.assertRaisesRegex(ValueError, "found 0"):
                plan_replacements(
                    repo, [0x00401000], old_type="char", new_type="bool")

            self.assertEqual(
                (repo / "src/game/TThing.cpp").read_text(), original)
