import unittest

from tools.mfc.library_link_surface_report import build_member_rows


class LibraryMemberReportTests(unittest.TestCase):
    def test_joins_pairing_state_and_recomp_module(self) -> None:
        decisions = [
            {"address": "0x401000", "library": "mfc", "member": "same.obj", "status": "already-modeled"},
            {"address": "0x402000", "library": "mfc", "member": "same.obj", "status": "oracle-ambiguous-review"},
        ]
        roadmap = [
            {"orig_addr": "0x401000", "pairing_state": "paired", "module": ""},
            {"orig_addr": "0x402000", "pairing_state": "unexplained", "module": ""},
            {"orig_addr": "", "pairing_state": "recomp_only", "module": "$NW\\same.obj"},
        ]
        self.assertEqual(
            build_member_rows(decisions, roadmap),
            [{
                "library": "mfc", "member": "same.obj", "oracle_rows": 2,
                "already_modeled": 1, "selected": 0, "paired": 1,
                "original_alias": 0, "unexplained": 1, "not_in_roadmap": 0,
                "recomp_only": 1,
            }],
        )


if __name__ == "__main__":
    unittest.main()
