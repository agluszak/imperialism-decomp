from __future__ import annotations

from pathlib import Path
import unittest

from tools.workflow.mac_payload_diff import build_report, load_records


REPO_ROOT = Path(__file__).resolve().parents[2]


class MacPayloadDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(REPO_ROOT)
        cls.records = load_records(REPO_ROOT)

    def test_report_covers_every_multi_instance_effective_class(self) -> None:
        counts: dict[str, int] = {}
        for record in self.records:
            counts[record["class"]] = counts.get(record["class"], 0) + 1
        expected = {class_name for class_name, count in counts.items() if count >= 2}
        self.assertEqual(set(self.report["classes"]), expected)
        self.assertEqual(self.report["summary"]["records"], 3263)
        self.assertEqual(self.report["summary"]["classes_with_multiple_instances"], 62)

    def test_deluxe_text_style_id_correlation_is_exact_and_high_confidence(self) -> None:
        partition = self.report["classes"]["TDeluxeText"]["segments"]["family_payload"][
            "partitions"
        ][0]
        self.assertIn(
            {
                "field": "family.text_style_id",
                "start": 32,
                "end": 34,
                "width": 2,
                "byte_order": "big",
                "distinct_values": 5,
                "confidence": "high",
            },
            partition["correlations"],
        )

    def test_existing_text_style_decoder_matches_correlated_serialized_bytes(self) -> None:
        deluxe = next(record for record in self.records if record["class"] == "TDeluxeText")
        raw = deluxe["segments"]["family_payload"]
        self.assertEqual(int.from_bytes(raw[32:34], "big"), deluxe["semantics"]["family.text_style_id"])

    def test_existing_picture_decoder_matches_correlated_serialized_bytes(self) -> None:
        picture = next(record for record in self.records if record["class"] == "TPictureButton")
        raw = picture["segments"]["family_payload"]
        self.assertEqual(int.from_bytes(raw[30:32], "big"), picture["semantics"]["family.picture_id"])

    def test_unexplained_varying_bytes_remain_visible(self) -> None:
        partition = self.report["classes"]["TPictureButton"]["segments"]["family_payload"][
            "partitions"
        ][0]
        self.assertGreater(partition["unexplained_varying_byte_count"], 0)
        self.assertTrue(partition["unexplained_varying_ranges"])

    def test_policy_rejects_windows_abi_inference(self) -> None:
        policy = self.report["policy"]
        self.assertIn("Mac resource", policy)
        self.assertIn("do not establish Windows ABI", policy)


if __name__ == "__main__":
    unittest.main()
