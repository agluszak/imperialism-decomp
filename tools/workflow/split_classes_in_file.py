#!/usr/bin/env python3
"""Split a mixed decompilation source file into class-named .cpp files.

The source file is rewritten to keep only global (non Class::) functions.
Each class function block is copied into src/game/<ClassName>.cpp.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-cpp", required=True, help="Mixed source file to split.")
    parser.add_argument(
        "--symbols-csv",
        default="config/symbols.csv",
        help="Symbols CSV used to map address -> symbol name.",
    )
    parser.add_argument("--module", default="IMPERIALISM")
    parser.add_argument(
        "--target-dir",
        default="src/game",
        help="Directory for generated class files (default: src/game).",
    )
    parser.add_argument(
        "--class-prefix",
        default="T",
        help="Only split classes with this prefix (default: T).",
    )
    return parser.parse_args()


def load_symbol_names(path: Path) -> dict[int, str]:
    mapping: dict[int, str] = {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="|")
        for row in reader:
            address = (row.get("address") or "").strip()
            name = (row.get("name") or "").strip()
            if not address or not name:
                continue
            try:
                mapping[int(address, 16)] = name
            except ValueError:
                continue
    return mapping


def annotation_re(module: str) -> re.Pattern[str]:
    return re.compile(
        r"^\s*//\s*FUNCTION:\s*"
        + re.escape(module)
        + r"\s+(0x[0-9a-fA-F]+)\s*$",
        re.MULTILINE,
    )


def split_blocks(text: str, module: str) -> tuple[str, list[tuple[int, str]]]:
    regex = annotation_re(module)
    matches = list(regex.finditer(text))
    if not matches:
        return text, []

    preamble = text[: matches[0].start()]
    blocks: list[tuple[int, str]] = []
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        addr = int(match.group(1), 16)
        block = text[start:end].rstrip() + "\n\n"
        blocks.append((addr, block))
    return preamble, blocks


def ensure_auto_inline_on(text: str) -> str:
    if "#pragma auto_inline(off)" in text and "#pragma auto_inline(on)" not in text:
        return text.rstrip() + "\n\n#if defined(_MSC_VER)\n#pragma auto_inline(on)\n#endif\n"
    return text


def main() -> int:
    args = parse_args()
    source_cpp = Path(args.source_cpp)
    symbols_csv = Path(args.symbols_csv)
    target_dir = Path(args.target_dir)

    if not source_cpp.exists():
        raise SystemExit(f"Source file not found: {source_cpp}")
    if not symbols_csv.exists():
        raise SystemExit(f"Symbols CSV not found: {symbols_csv}")

    symbol_names = load_symbol_names(symbols_csv)
    source_text = source_cpp.read_text(encoding="utf-8", errors="ignore")
    preamble, blocks = split_blocks(source_text, args.module)
    if not blocks:
        raise SystemExit(f"No FUNCTION blocks found in {source_cpp}")

    by_class: dict[str, list[tuple[int, str]]] = {}
    globals_: list[tuple[int, str]] = []

    for addr, block in blocks:
        name = symbol_names.get(addr, "")
        if "::" not in name:
            globals_.append((addr, block))
            continue
        class_name = name.split("::", 1)[0].strip()
        if not class_name.startswith(args.class_prefix):
            globals_.append((addr, block))
            continue
        by_class.setdefault(class_name, []).append((addr, block))

    target_dir.mkdir(parents=True, exist_ok=True)

    for class_name, class_blocks in sorted(by_class.items()):
        class_blocks.sort(key=lambda item: item[0])
        out_path = target_dir / f"{class_name}.cpp"
        out_text = preamble.rstrip() + "\n\n" + "".join(block for _, block in class_blocks)
        out_text = ensure_auto_inline_on(out_text)
        out_path.write_text(out_text, encoding="utf-8")
        print(f"Wrote {out_path} ({len(class_blocks)} functions)")

    globals_.sort(key=lambda item: item[0])
    rewritten_source = preamble.rstrip() + "\n\n" + "".join(block for _, block in globals_)
    rewritten_source = ensure_auto_inline_on(rewritten_source)
    source_cpp.write_text(rewritten_source, encoding="utf-8")
    print(f"Rewrote {source_cpp} with {len(globals_)} global function(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
