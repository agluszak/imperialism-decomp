"""Authored selection, native Ghidriff outcomes, and catalog-only address lookup."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from reccmp.types import ImageId

from tools.common.reccmp_report import function_counts, run_report
from tools.reccmp.addr_translate import load_entities
from tools.reccmp.compare_batch import authored_claims, select_addresses
from tools.source_model import Claim, SourceModel


class ReccmpReportTests(unittest.TestCase):
    def test_report_rejects_changed_pdb_and_wrong_native_binary(self) -> None:
        for failure in ("changed-pdb", "wrong-binary"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                inputs = {name: root / name for name in ("orig", "recomp", "pdb")}
                for name, path in inputs.items():
                    path.write_bytes(name.encode())
                (root / "evidence.gpr").touch()
                target = SimpleNamespace(
                    original_path=inputs["orig"],
                    recompiled_path=inputs["recomp"],
                    recompiled_pdb=inputs["pdb"],
                    source_index=None,
                )
                output = root / "report"

                def compare(*args, **kwargs):
                    summary = {
                        "functions": [{"orig": "0x1", "outcome": "differences"}],
                        "inputs": {
                            image: {
                                "sha256": hashlib.sha256(
                                    inputs[image].read_bytes()
                                ).hexdigest()
                            }
                            for image in ("orig", "recomp")
                        },
                    }
                    if failure == "changed-pdb":
                        inputs["pdb"].write_bytes(b"rebuilt")
                    else:
                        summary["inputs"]["recomp"]["sha256"] = "wrong"
                    (output / "summary.json").write_text(json.dumps(summary))
                    return SimpleNamespace(returncode=0)

                with (
                    patch("tools.common.reccmp_report.ghidra_env") as environment,
                    patch("tools.common.reccmp_report.RecCmpProject") as project,
                    patch(
                        "tools.common.reccmp_report.subprocess.run", side_effect=compare
                    ),
                ):
                    environment.project_location.return_value = root
                    environment.project_name.return_value = "evidence"
                    project.from_directory.return_value.get.return_value = target
                    with self.assertRaisesRegex(
                        ValueError, "inputs changed|different input binaries"
                    ):
                        run_report(
                            "TEST",
                            root,
                            orig_addresses=[1],
                            output=output,
                            selection={},
                        )
                self.assertTrue((output / "selection.json").is_file())

    def test_counts_distinguish_inline_retry_from_direct_clean_result(self) -> None:
        rows = [
            {"outcome": "no-differences", "inline_normalized_diff": None},
            {"outcome": "no-differences", "inline_normalized_diff": []},
            {"outcome": "differences", "inline_normalized_diff": ["changed"]},
            {"outcome": "unpaired", "inline_normalized_diff": None},
            {"outcome": "analysis-failed", "inline_normalized_diff": None},
        ]
        self.assertEqual(
            function_counts(rows),
            {
                "outcomes": {
                    "no-differences": 2,
                    "differences": 1,
                    "unpaired": 1,
                    "analysis-failed": 1,
                },
                "inline_retries": 2,
                "inline_retries_clean": 1,
            },
        )

    def test_authored_selection_excludes_generated_and_compiler_claims(self) -> None:
        claims = {
            address: Claim(address, kind, "src/test.cpp", 1, origin=origin)
            for address, kind, origin in (
                (1, "FUNCTION", "marker"),
                (2, "SYNTHETIC", "marker"),
                (3, "TEMPLATE", "marker"),
                (4, "LIBRARY", "marker"),
                (5, "STUB", "marker"),
                (6, "FUNCTION", "generated"),
            )
        }
        with patch(
            "tools.reccmp.compare_batch.build_model",
            return_value=SourceModel("IMPERIALISM", functions=claims),
        ):
            self.assertEqual(set(authored_claims(Path("."), "IMPERIALISM")), {1})

    def test_header_selection_uses_native_transitive_dependencies(self) -> None:
        claims = {
            1: Claim(1, "FUNCTION", "src/a.cpp", 1),
            2: Claim(2, "FUNCTION", "src/b.cpp", 1),
        }
        self.assertEqual(
            select_addresses(
                claims,
                [],
                ["include/a.h"],
                dependencies={
                    "src/a.cpp": ("include/a.h",),
                    "src/b.cpp": ("include/b.h",),
                },
            ),
            [1],
        )
        with self.assertRaises(ValueError):
            select_addresses(claims, [], ["include/a.h"])

    def test_missing_address_is_not_silently_dropped(self) -> None:
        with self.assertRaises(ValueError):
            select_addresses({}, ["0x401000"], [])

    def test_address_translation_queries_both_images_with_original_precedence(
        self,
    ) -> None:
        original = SimpleNamespace(
            orig_addr=1, recomp_addr=2, best_name=lambda: "Original"
        )
        rebuilt = SimpleNamespace(
            orig_addr=3, recomp_addr=4, best_name=lambda: "Rebuilt"
        )
        catalog = Mock()
        catalog.get.side_effect = [original, None, rebuilt]
        with patch("tools.reccmp.addr_translate.load_catalog", return_value=catalog):
            rows = load_entities("IMPERIALISM", Path("build"), [1, 4])
        self.assertEqual(
            catalog.get.call_args_list,
            [((ImageId.ORIG, 1),), ((ImageId.ORIG, 4),), ((ImageId.RECOMP, 4),)],
        )
        self.assertEqual(
            [row["direction"] for row in rows], ["orig->recomp", "recomp->orig"]
        )
        self.assertEqual(rows[1]["orig"], 3)


if __name__ == "__main__":
    unittest.main()
