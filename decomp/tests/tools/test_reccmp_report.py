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
                    target_id="TEST",
                    original_path=inputs["orig"],
                    recompiled_path=inputs["recomp"],
                    recompiled_pdb=inputs["pdb"],
                    source_index=None,
                )
                output = root / "report"
                manifest = SimpleNamespace(
                    functions=[SimpleNamespace(orig_addr=1)], to_json=dict
                )

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
                    patch("tools.common.reccmp_report.Compare"),
                    patch(
                        "tools.common.reccmp_report.build_manifest",
                        return_value=manifest,
                    ),
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
                self.assertTrue((output / "manifest.json").is_file())

    def test_counts_read_producer_selected_pass(self) -> None:
        def row(outcome, selected="ordinary", signature=None, score=None):
            evidence = {
                "outcome": outcome,
                "signature_diff": signature,
                "similarity": score,
                "body_diff": [] if outcome == "no-differences" else ["-a", "+b"],
                "data": [],
                "change_kind": "body",
            }
            passes = {"ordinary": {"outcome": "differences", "signature_diff": None}}
            passes[selected] = evidence
            return {"outcome": outcome, "selected_pass": selected, "passes": passes}

        rows = [
            row("no-differences", score=1.0),
            row("no-differences", signature=["-int", "+bool"], score=1.0),
            row("no-differences", "inline", score=1.0),
            row("differences", "inline", score=0.5),
            row("unpaired"),
            row("analysis-failed"),
        ]
        self.assertEqual(
            function_counts(rows),
            {
                "outcomes": {
                    "no-differences": 3,
                    "differences": 1,
                    "unpaired": 1,
                    "analysis-failed": 1,
                },
                "clean_rate": 0.75,
                "similarity": {"mean": 0.875, "median": 1.0, "scored": 4, "unscored": 0},
                "code_differences": 1,
                "data_differences": 0,
                "signature_differences": 1,
                "scalar_signedness_differences": 0,
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
