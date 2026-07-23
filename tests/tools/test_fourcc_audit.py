from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.workflow import fourcc_audit


CATALOG = "include/game/ui_tags_common.h"


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class FourCcAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(fourcc_audit, "CATALOGS", {CATALOG: "ui_tag_shared"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_characters_define_the_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, CATALOG, "const int kControlTagDialog = IMPERIALISM_FOURCC('D', 'L', 'O', 'G');\n")
            _write(root, "src/game/Test.cpp", "int f() { return kControlTagDialog; }\n")

            tags, violations = fourcc_audit.collect(root)

            self.assertEqual([tag.characters for tag in tags], ["DLOG"])
            self.assertEqual([tag.value for tag in tags], [0x444C4F47])
            self.assertEqual(violations, [])

    def test_raw_hex_and_multi_character_spellings_are_violations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, CATALOG, "const int kControlTagDialog = IMPERIALISM_FOURCC('D', 'L', 'O', 'G');\n")
            _write(
                root,
                "src/game/Test.cpp",
                "int f() { return 0x444c4f47; }\n"
                "int g() { return 'text'; }\n",
            )

            _, violations = fourcc_audit.collect(root)

            self.assertEqual(
                sorted(violation.kind for violation in violations),
                ["multi_character_literal", "raw_hex_tag_spelling"],
            )

    def test_block_comments_and_escapes_are_not_violations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, CATALOG, "const int kControlTagDialog = IMPERIALISM_FOURCC('D', 'L', 'O', 'G');\n")
            _write(
                root,
                "src/game/Test.cpp",
                "int f() { return kControlTagDialog; /* was 0x444c4f47 'DLOG' */ }\n"
                "char pair[2] = {'P', 'L'};\n"
                "char nul = '\\0';\n",
            )

            _, violations = fourcc_audit.collect(root)

            self.assertEqual(violations, [])

    def test_duplicate_values_are_violations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                CATALOG,
                "const int kControlTagDialog = IMPERIALISM_FOURCC('D', 'L', 'O', 'G');\n"
                "const int kControlTagGold = IMPERIALISM_FOURCC('D', 'L', 'O', 'G');\n",
            )
            _write(root, "src/game/Test.cpp", "int f() { return 0; }\n")

            _, violations = fourcc_audit.collect(root)

            self.assertEqual([violation.kind for violation in violations], ["duplicate_tag_value"])


if __name__ == "__main__":
    unittest.main()
