"""Address-filtered execution of shared reccmp reports."""

from pathlib import Path
from contextlib import redirect_stdout
import io
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from reccmp.compare.diagnosis import ComparisonAnalysis
from reccmp.compare.report import ReccmpComparedEntity

from tools.common.reccmp_report import run_report
from tools.reccmp.addr_translate import load_entities
from tools.reccmp.compare_batch import main as compare_batch_main


class ReccmpReportTests(unittest.TestCase):
    def test_run_report_pairs_all_symbols_before_filtering_addresses(self) -> None:
        target = SimpleNamespace(
            original_path=Path("Imperialism.exe"),
            report_config=SimpleNamespace(ignore_functions=[]),
        )
        compare = Mock(orig_source_digest="digest")
        compare.compare_addresses.return_value = [
            ReccmpComparedEntity(
                orig_addr=0x401000, name="TExample::Run", accuracy=1.0,
                recomp_addr=0x501000, analysis=ComparisonAnalysis.exact(),
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            build_dir = Path(directory)
            with (
                patch("tools.common.reccmp_report.RecCmpProject.from_directory") as project,
                patch("tools.common.reccmp_report.Compare.from_target", return_value=compare) as setup,
            ):
                project.return_value.get.return_value = target
                rows = run_report(
                    "IMPERIALISM", build_dir, diet=True,
                    orig_addresses=[0x402000, 0x401000, 0x401000],
                    recomp_addresses=[0x501000],
                )

        project.assert_called_once_with(build_dir.resolve())
        project.return_value.get.assert_called_once_with("IMPERIALISM")
        setup.assert_called_once_with(target)
        compare.compare_addresses.assert_called_once_with(
            [0x401000, 0x402000], [0x501000],
            include_diff=False, include_exact_diff=False,
        )
        self.assertEqual(rows[0]["address"], "0x401000")
        self.assertEqual(rows[0]["recomp"], "0x501000")
        self.assertEqual(rows[0]["comparison"], {"status": "exact"})

    def test_address_translation_queries_both_images(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build_dir = Path(directory)
            with patch(
                "tools.reccmp.addr_translate.run_report", return_value=[]
            ) as report:
                self.assertEqual(
                    load_entities(
                        "IMPERIALISM", build_dir, [0x401000, 0x501000]
                    ),
                    [],
                )

        report.assert_called_once_with(
            "IMPERIALISM",
            build_dir,
            diet=True,
            orig_addresses=[0x401000, 0x501000],
            recomp_addresses=[0x401000, 0x501000],
        )

    def test_compare_batch_requests_only_wanted_addresses(self) -> None:
        rows = [
            {
                "address": hex(address),
                "name": f"function_{address}",
                "matching": 1.0,
                "comparison": {"status": "exact"},
            }
            for address in (0x401000, 0x402000)
        ]
        argv = [
            "compare_batch",
            "--target",
            "IMPERIALISM",
            "--build-dir",
            "build-msvc500",
            "0x402000",
            "0x401000",
        ]
        with (
            patch("tools.reccmp.compare_batch.run_report", return_value=rows) as report,
            patch("sys.argv", argv),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(compare_batch_main(), 0)

        self.assertEqual(
            report.call_args.kwargs["orig_addresses"], {0x401000, 0x402000}
        )
        self.assertTrue(report.call_args.kwargs["diet"])


if __name__ == "__main__":
    unittest.main()
