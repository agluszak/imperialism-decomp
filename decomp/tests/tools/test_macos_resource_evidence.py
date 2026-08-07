from __future__ import annotations

import csv
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools.workflow import macos_resource_evidence as oracle


REPO_ROOT = Path(__file__).resolve().parents[2]


def _pascal(text: str) -> bytes:
    encoded = text.encode("mac_roman")
    return bytes([len(encoded)]) + encoded


def _macbinary(name: str, data_fork: bytes, resource_fork: bytes) -> bytes:
    header = bytearray(128)
    encoded_name = name.encode("mac_roman")
    header[1] = len(encoded_name)
    header[2 : 2 + len(encoded_name)] = encoded_name
    struct.pack_into(">I", header, 83, len(data_fork))
    struct.pack_into(">I", header, 87, len(resource_fork))
    padding = bytes((-len(data_fork)) % 128)
    return bytes(header) + data_fork + padding + resource_fork


def _resource_fork(
    entries: list[tuple[str, int, str | None, int, bytes]],
) -> bytes:
    data_area = bytearray()
    data_offsets: list[int] = []
    for _type_code, _resource_id, _name, _attributes, payload in entries:
        data_offsets.append(len(data_area))
        data_area.extend(struct.pack(">I", len(payload)))
        data_area.extend(payload)

    type_codes = list(dict.fromkeys(entry[0] for entry in entries))
    name_list = bytearray()
    name_offsets: list[int] = []
    for _type_code, _resource_id, name, _attributes, _payload in entries:
        if name is None:
            name_offsets.append(-1)
        else:
            name_offsets.append(len(name_list))
            name_list.extend(_pascal(name))

    grouped_indexes = [
        [index for index, entry in enumerate(entries) if entry[0] == type_code]
        for type_code in type_codes
    ]
    type_entries_size = 2 + 8 * len(type_codes)
    reference_offset = type_entries_size
    type_list = bytearray(struct.pack(">H", len(type_codes) - 1))
    references = bytearray()
    for type_code, indexes in zip(type_codes, grouped_indexes, strict=True):
        type_list.extend(type_code.encode("mac_roman"))
        type_list.extend(struct.pack(">HH", len(indexes) - 1, reference_offset))
        for index in indexes:
            _type_code, resource_id, _name, attributes, _payload = entries[index]
            references.extend(struct.pack(">hh", resource_id, name_offsets[index]))
            references.append(attributes)
            references.extend(data_offsets[index].to_bytes(3, "big"))
            references.extend(bytes(4))
        reference_offset += 12 * len(indexes)
    type_list.extend(references)

    data_offset = 0x100
    map_offset = data_offset + len(data_area)
    type_list_offset = 28
    name_list_offset = type_list_offset + len(type_list)
    map_length = name_list_offset + len(name_list)
    header = struct.pack(">IIII", data_offset, map_offset, len(data_area), map_length)
    resource_map = bytearray(map_length)
    resource_map[:16] = header
    struct.pack_into(">HH", resource_map, 24, type_list_offset, name_list_offset)
    resource_map[type_list_offset:name_list_offset] = type_list
    resource_map[name_list_offset:] = name_list

    fork = bytearray(map_offset + map_length)
    fork[:16] = header
    fork[data_offset:map_offset] = data_area
    fork[map_offset:] = resource_map
    return bytes(fork)


def _widget_record(
    type_code: str,
    tag: str,
    class_name: str,
    x: int,
    y: int,
    width: int,
    height: int,
    children: bytes = b"",
) -> bytes:
    family_size = oracle.FAMILY_MINIMUM_SIZES[type_code]
    family = type_code.encode("ascii") + bytes(family_size - 4)
    payload = b"".join(
        [
            _pascal(class_name),
            tag.encode("ascii"),
            b"\0",
            b"\x7f\xff\xff\xff",
            b"\0\0\x03\0",
            struct.pack(">iiii", y, x, height, width),
            bytes(22),
            family,
            children,
        ]
    )
    return type_code.encode("ascii") + struct.pack(">I", 4 + len(payload)) + payload


def _startup_view() -> bytes:
    children = b"".join(
        _widget_record(type_code, tag, class_name, x, y, width, height)
        for type_code, tag, class_name, x, y, width, height in oracle.EXPECTED_STARTUP_1500[1:]
    )
    root = oracle.EXPECTED_STARTUP_1500[0]
    return b"\x03\0\0\x03" + _widget_record(*root, children=children)


def _txst(
    face: int = 1,
    point_size: int = 12,
    color: tuple[int, int, int] = (0x1111, 0x2222, 0x3333),
    font_name: str = "Geneva",
) -> bytes:
    return (
        bytes((face, 0xA5))
        + struct.pack(">hHHH", point_size, *color)
        + _pascal(font_name)
    )


def _styl() -> bytes:
    run = struct.pack(">IhhhBBhHHH", 0, 16, 12, 0, 1, 0x5A, 12, 0, 0, 0)
    return struct.pack(">H", 1) + run


class MacosResourceEvidenceTests(unittest.TestCase):
    def test_extracts_aligned_macbinary_resource_fork(self) -> None:
        resource_fork = b"resource-fork"
        blob = _macbinary("Startup.rsrc", b"data", resource_fork)

        name, extracted = oracle.extract_macbinary_resource_fork(blob)

        self.assertEqual(name, "Startup.rsrc")
        self.assertEqual(extracted, resource_fork)

    def test_parses_resource_map_names_attributes_and_payloads(self) -> None:
        fork = _resource_fork(
            [
                ("STR#", 1500, "Setup text", 0x20, b"first"),
                ("STR#", -1, None, 0, b"second"),
                ("PICT", 42, "Map", 0, b"picture"),
            ]
        )

        entries = oracle.parse_resource_fork("Fixture.rsrc", fork)

        self.assertEqual(
            [(entry.type_code, entry.resource_id, entry.name) for entry in entries],
            [("STR#", 1500, "Setup text"), ("STR#", -1, ""), ("PICT", 42, "Map")],
        )
        self.assertEqual(entries[0].attributes, 0x20)
        self.assertEqual(
            [entry.data for entry in entries], [b"first", b"second", b"picture"]
        )

    def test_decodes_string_lists_and_picture_bounds(self) -> None:
        strings = struct.pack(">H", 2) + _pascal("New Game") + _pascal("Quit")
        picture = struct.pack(">Hhhhh", 10, 4, 7, 104, 207)

        self.assertEqual(oracle.decode_string_list(strings), ["New Game", "Quit"])
        self.assertEqual(oracle.decode_picture_bounds(picture), (7, 4, 200, 100))

    def test_decodes_txst_and_textedit_style_runs(self) -> None:
        style = oracle.ResourceEntry("Fixture.rsrc", "TxSt", 7, "", 0, _txst())
        text = oracle.ResourceEntry("Fixture.rsrc", "TEXT", 8, "", 0, b"Styled text")
        scrap = oracle.ResourceEntry("Fixture.rsrc", "styl", 8, "", 0, _styl())

        decoded_style = oracle.decode_txst(style)
        decoded_scrap = oracle.decode_styl(scrap, text)

        self.assertEqual(decoded_style["font_name"], "Geneva")
        self.assertEqual(decoded_style["face_flag_names"], ["bold"])
        self.assertEqual(decoded_style["foreground_color"]["hex"], "#111122223333")
        run = decoded_scrap["runs"][0]
        self.assertEqual((run["start"], run["end"]), (0, len(text.data)))
        self.assertEqual((run["line_height"], run["ascent"], run["leading"]), (16, 12, 4))
        with self.assertRaisesRegex(oracle.ResourceFormatError, "require"):
            oracle.decode_styl(
                oracle.ResourceEntry("Fixture.rsrc", "styl", 9, "", 0, b"\0\x01"),
                text,
            )

    def test_decodes_nested_startup_widgets(self) -> None:
        view = oracle.ResourceEntry(
            "Startup.rsrc", "View", 1500, "Startup", 0, _startup_view()
        )

        widgets = oracle.decode_widgets([view])

        self.assertEqual(oracle.validate_startup_1500(widgets), [])
        self.assertEqual(widgets[0].depth, 0)
        self.assertEqual(widgets[0].parent_offset, None)
        self.assertTrue(all(widget.depth == 1 for widget in widgets[1:]))
        self.assertTrue(all(widget.parent_tag == "base" for widget in widgets[1:]))

    def test_builds_typed_hierarchical_ui_ir(self) -> None:
        resources = [
            oracle.ResourceEntry(
                "Startup.rsrc", "View", 1500, "Startup", 0, _startup_view()
            )
        ]
        widgets = oracle.decode_widgets(resources)

        ui_ir = oracle.build_ui_ir(resources, widgets)

        self.assertEqual(ui_ir["format_version"], oracle.EVIDENCE_VERSION)
        view = ui_ir["views"][0]
        self.assertEqual((view["resource_file"], view["view_id"]), ("Startup.rsrc", 1500))
        root, child = view["nodes"][:2]
        expected_root = oracle.EXPECTED_STARTUP_1500[0]
        self.assertEqual(
            root["geometry"],
            {
                "x": expected_root[3],
                "y": expected_root[4],
                "width": expected_root[5],
                "height": expected_root[6],
            },
        )
        self.assertIsNone(root["parent_offset"])
        self.assertEqual(child["parent_offset"], root["offset"])
        self.assertIsInstance(child["type_value"], int)
        self.assertIsInstance(child["tag_value"], int)
        self.assertEqual(child["decoder_confidence"], "high")
        self.assertEqual(oracle.validate_ui_ir_structure(ui_ir), [])

    def test_rejects_overlapping_siblings(self) -> None:
        resources = [
            oracle.ResourceEntry(
                "Startup.rsrc", "View", 1500, "Startup", 0, _startup_view()
            )
        ]
        ui_ir = oracle.build_ui_ir(resources, oracle.decode_widgets(resources))
        nodes = ui_ir["views"][0]["nodes"]
        nodes[1]["record_end"] = nodes[2]["offset"] + 1

        errors = oracle.validate_ui_ir_structure(ui_ir)

        self.assertTrue(any("sibling records" in error for error in errors))

    def test_committed_real_resource_sentinels(self) -> None:
        ui_ir = json.loads(
            (
                REPO_ROOT
                / "vendor/macos_codewarrior/evidence/resources/ui_views.json"
            ).read_text(encoding="utf-8")
        )

        text_resources = json.loads(
            (
                REPO_ROOT
                / "vendor/macos_codewarrior/evidence/resources/text_resources.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(oracle.validate_real_ui_sentinels(ui_ir), [])
        self.assertEqual(
            oracle.validate_real_text_resource_sentinels(text_resources), []
        )

    def test_writes_deterministic_resource_evidence(self) -> None:
        strings = struct.pack(">H", 2) + _pascal("New Game") + _pascal("Quit")
        resources = [
            oracle.ResourceEntry(
                "Startup.rsrc", "View", 1500, "Startup", 0, _startup_view()
            ),
            oracle.ResourceEntry(
                "Startup.rsrc",
                "PICT",
                1500,
                "Startup",
                0,
                struct.pack(">Hhhhh", 10, 0, 0, 480, 640),
            ),
            oracle.ResourceEntry("Startup.rsrc", "STR#", 1500, "Setup", 0, strings),
            oracle.ResourceEntry("Startup.rsrc", "TxSt", 1500, "Setup style", 0, _txst()),
            oracle.ResourceEntry("Startup.rsrc", "TEXT", 1600, "Help", 0, b"Styled text"),
            oracle.ResourceEntry("Startup.rsrc", "styl", 1600, "Help", 0, _styl()),
        ]
        with (
            tempfile.TemporaryDirectory() as first_dir,
            tempfile.TemporaryDirectory() as second_dir,
        ):
            first = Path(first_dir)
            second = Path(second_dir)

            summary = oracle.write_outputs(first, resources)
            oracle.write_outputs(second, list(reversed(resources)))

            self.assertEqual(summary["widgets"], len(oracle.EXPECTED_STARTUP_1500))
            self.assertEqual(
                {path.name: path.read_bytes() for path in first.iterdir()},
                {path.name: path.read_bytes() for path in second.iterdir()},
            )
            with (first / "pictures.csv").open(encoding="utf-8", newline="") as stream:
                picture = next(csv.DictReader(stream))
            self.assertEqual(
                (picture["x"], picture["y"], picture["width"], picture["height"]),
                ("0", "0", "640", "480"),
            )
            text_resources = json.loads(
                (first / "text_resources.json").read_text(encoding="utf-8")
            )
            self.assertEqual(text_resources["texts"][0]["text"], "Styled text")
            self.assertEqual(text_resources["style_scraps"][0]["run_count"], 1)


if __name__ == "__main__":
    unittest.main()
