from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from imperialism_re.core.catalog import catalog_map, load_catalog
from imperialism_re.core.runtime import WriterLockError, writer_lock


class ToolingSmokeTests(unittest.TestCase):
    def test_catalog_has_expected_size(self) -> None:
        catalog = load_catalog()
        self.assertEqual(50, len(catalog))

    def test_catalog_modules_import(self) -> None:
        for spec in load_catalog():
            module = importlib.import_module(spec.module)
            self.assertTrue(hasattr(module, "main"), spec.module)

    def test_cli_help_for_all_commands(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC}:{env.get('PYTHONPATH', '')}".rstrip(":")
        for name in sorted(catalog_map()):
            proc = subprocess.run(
                [sys.executable, "-m", "imperialism_re.cli", name, "--help"],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                0,
                proc.returncode,
                msg=f"{name} failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )

    def test_writer_lock_blocks_second_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with writer_lock(root, blocking=False):
                with self.assertRaises(WriterLockError):
                    with writer_lock(root, blocking=False):
                        pass

    def test_no_legacy_ghidra_console_context_in_commands(self) -> None:
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("currentProgram", text, msg=str(path))

    def test_no_hardcoded_home_paths_in_package(self) -> None:
        for path in (SRC / "imperialism_re").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("/home/", text, msg=str(path))

    def test_no_local_parse_helpers_in_commands(self) -> None:
        pattern = re.compile(r"^def (parse_hex|parse_int)\(", re.MULTILINE)
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(
                pattern.search(text),
                msg=f"shared parser helper expected from core.typing_utils: {path}",
            )

    def test_no_direct_pyghidra_session_bootstrap_in_commands(self) -> None:
        banned = (
            "pyghidra.start(",
            "pyghidra.program_context(",
            "open_project_with_lock_cleanup(",
        )
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in banned:
                self.assertNotIn(
                    token,
                    text,
                    msg=f"command should rely on core.ghidra_session.open_program: {path}",
                )

    def test_no_magic_repo_root_resolution_in_commands(self) -> None:
        banned = "Path(__file__).resolve().parents[3]"
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(
                banned,
                text,
                msg=f"use core.config helpers instead of magic parent traversal: {path}",
            )

    def test_no_cross_command_imports(self) -> None:
        pattern = re.compile(r"from imperialism_re\.commands\.[A-Za-z0-9_]+ import")
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(
                pattern.search(text),
                msg=f"shared helpers must live under imperialism_re.core: {path}",
            )

    def test_no_raw_sys_argv_parsing_in_commands(self) -> None:
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(
                "sys.argv[",
                text,
                msg=f"command should use argparse consistently: {path}",
            )

    def test_no_positional_project_root_args(self) -> None:
        pattern = re.compile(r"add_argument\(\s*[\"'](?:project_root|legacy_project_root)[\"']")
        for path in (SRC / "imperialism_re" / "commands").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(
                pattern.search(text),
                msg=f"use --project-root option; positional project_root is retired: {path}",
            )


if __name__ == "__main__":
    unittest.main()
