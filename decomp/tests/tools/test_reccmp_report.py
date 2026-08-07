"""Address-filtered execution of shared reccmp reports."""

from pathlib import Path
from contextlib import redirect_stdout
import io
import tempfile
import unittest
from unittest.mock import patch

from tools.common.reccmp_report import run_report
from tools.reccmp.addr_translate import load_entities
from tools.reccmp.compare_batch import main as compare_batch_main


class ReccmpReportTests(unittest.TestCase):
    def test_run_report_passes_deduplicated_address_filters(self) -> None:
        expected = [{"address": "0x401000"}]

        def write_report(command, **_kwargs):
            report_path = Path(command[command.index("--json") + 1])
            report_path.write_text(
                '{"format":1,"data":[{"address":"0x401000"}]}',
                encoding="utf-8",
            )

        with tempfile.TemporaryDirectory() as directory:
            build_dir = Path(directory)
            with patch(
                "tools.common.reccmp_report.subprocess.run", side_effect=write_report
            ) as run:
                rows = run_report(
                    "IMPERIALISM",
                    build_dir,
                    diet=True,
                    orig_addresses=[0x402000, 0x401000, 0x401000],
                    recomp_addresses=[0x501000],
                )

        self.assertEqual(rows, expected)
        command = run.call_args.args[0]
        self.assertIn("--json-diet", command)
        self.assertEqual(
            command[command.index("--orig-address") :],
            [
                "--orig-address",
                "0x401000",
                "--orig-address",
                "0x402000",
                "--recomp-address",
                "0x501000",
            ],
        )

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
