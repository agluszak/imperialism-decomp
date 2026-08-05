from __future__ import annotations

import struct
import unittest

from tools.workflow.pe_resources import (
    build_bitmap_file,
    build_cursor_file,
    build_icon_file,
    build_turn_event_cursor_rc,
    parse_group_cursor,
)


class PeCursorResourceTests(unittest.TestCase):
    def test_reconstructs_icon_file_from_group_and_image_resources(self) -> None:
        image = struct.pack("<IiiHH", 40, 32, 64, 1, 4) + bytes(64)
        group = struct.pack("<HHHBBBBHHIH", 0, 1, 1, 32, 32, 16, 0, 1, 4, len(image), 7)

        icon = build_icon_file(group, {7: image})

        self.assertEqual(struct.unpack_from("<HHH", icon, 0), (0, 1, 1))
        self.assertEqual(struct.unpack_from("<BBBBHHII", icon, 6),
                         (32, 32, 16, 0, 1, 4, len(image), 22))
        self.assertEqual(icon[22:], image)

    def test_wraps_indexed_bitmap_resource_without_changing_dib(self) -> None:
        dib_header = struct.pack(
            "<IiiHHIIiiII", 40, 2, 2, 1, 8, 0, 8, 0, 0, 2, 0
        )
        palette = bytes((0, 0, 0, 0, 0, 0, 255, 0))
        pixels = bytes((0, 1, 0, 0, 1, 0, 0, 0))
        dib = dib_header + palette + pixels

        bitmap = build_bitmap_file(dib)

        self.assertEqual(bitmap[:2], b"BM")
        self.assertEqual(struct.unpack_from("<I", bitmap, 2)[0], len(bitmap))
        self.assertEqual(struct.unpack_from("<I", bitmap, 10)[0], 14 + 40 + 8)
        self.assertEqual(bitmap[14:], dib)

    def test_reconstructs_cursor_file_with_resource_hotspot(self) -> None:
        image = struct.pack("<IiiHH", 40, 32, 64, 1, 4) + bytes(64)
        resource_blob = struct.pack("<HH", 2, 7) + image
        group_blob = struct.pack("<HHH", 0, 2, 1) + struct.pack(
            "<HHHHIH", 32, 64, 1, 4, len(resource_blob), 36
        )

        cursor_file = build_cursor_file(group_blob, {36: resource_blob})

        self.assertEqual(struct.unpack_from("<HHH", cursor_file), (0, 2, 1))
        self.assertEqual(
            struct.unpack_from("<BBBBHHII", cursor_file, 6),
            (32, 32, 16, 0, 2, 7, len(image), 22),
        )
        self.assertEqual(cursor_file[22:], image)

    def test_rejects_missing_cursor_image_resource(self) -> None:
        group_blob = struct.pack("<HHH", 0, 2, 1) + struct.pack(
            "<HHHHIH", 32, 64, 1, 4, 100, 36
        )

        with self.assertRaisesRegex(ValueError, "missing CURSOR id 36"):
            build_cursor_file(group_blob, {})

    def test_rejects_truncated_group_directory(self) -> None:
        group_blob = struct.pack("<HHH", 0, 2, 1)

        with self.assertRaisesRegex(ValueError, "expected 20"):
            parse_group_cursor(group_blob)

    def test_cursor_rc_uses_unquoted_named_resource_identifiers(self) -> None:
        rc = build_turn_event_cursor_rc(["~C1001.cur", "~C1000.cur"])

        self.assertIn(b'\n~C1000 CURSOR DISCARDABLE "cursors/~C1000.cur"\n', rc)
        self.assertNotIn(b'\n"~C1000" CURSOR', rc)


if __name__ == "__main__":
    unittest.main()
