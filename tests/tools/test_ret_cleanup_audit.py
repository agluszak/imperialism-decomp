import unittest

from tools.workflow.ret_cleanup_audit import cleanup, ret_contract


class RetCleanupAuditTests(unittest.TestCase):
    def test_cleanup_parses_plain_and_immediate_returns(self):
        self.assertEqual(cleanup("ret"), 0)
        self.assertEqual(cleanup("ret 0xc\t(file.cpp:1)"), 12)
        self.assertIsNone(cleanup("mov eax, ecx"))

    def test_ret_contract_reads_both_and_one_sided_rows(self):
        entity = {
            "diff": [
                [
                    "@@",
                    [
                        {"both": [["0x1", "ret 4", "0x2"]]},
                        {"orig": [["0x3", "ret 8"]], "recomp": [["0x4", "ret 0xc"]]},
                    ],
                ]
            ]
        }
        self.assertEqual(ret_contract(entity), ({4, 8}, {4, 12}))
