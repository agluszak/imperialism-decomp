import unittest

from tools.workflow.cstring_runtime_probe import PROBE_SOURCE, SUCCESS_LINE


class CStringRuntimeProbeTest(unittest.TestCase):
    def test_probe_uses_public_cstring_surface_for_required_lifetimes(self):
        self.assertIn("sizeof(CString) == 4", PROBE_SOURCE)
        self.assertIn("CString values[3]", PROBE_SOURCE)
        self.assertIn("GetBufferSetLength(5)", PROBE_SOURCE)
        self.assertIn("ReleaseBuffer(5)", PROBE_SOURCE)
        self.assertIn("return prefix + suffix", PROBE_SOURCE)
        self.assertIn("throw 7", PROBE_SOURCE)
        self.assertIn("UnwindSentinel::destroyed == 1", PROBE_SOURCE)

    def test_probe_does_not_read_mfc_string_internals(self):
        self.assertNotIn("m_pchData", PROBE_SOURCE)
        self.assertNotIn("CStringData", PROBE_SOURCE)
        self.assertNotIn("GetData", PROBE_SOURCE)
        self.assertIn(SUCCESS_LINE, PROBE_SOURCE)


if __name__ == "__main__":
    unittest.main()
