# tabsenu.gob Findings

Date: 2026-02-16
Source file: `/home/andrzej.gluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Data/tabsenu.gob`

## High-level
- `tabsenu.gob` is a PE resource container (DLL-style) that exposes `TABLE` resources.
- It is primarily scenario/map/news table data, not the main UI stringtable container.
- UI/dialog text lookup still appears to come from `STR#ENU.GOB`.

## Extraction notes
- Listing works with:
  - `wrestool -l tabsenu.gob`
- Raw extraction requires output directory:
  - `wrestool -x --raw --type=TABLE -o <out_dir> tabsenu.gob`
- Workspace extraction (2026-02-16):
  - source: `Data/tabsenu.gob`
  - output: `Data/extracted_tables/tabsenu`
  - total extracted files: `43`
  - note: resource names containing `/` (e.g. `DATA/001.TAB`) require creating nested output path `tabsenu.gob_TABLE_DATA/` before rerun.

## Extracted resource groups (observed)
- `tabsenu.gob_TABLE_NEWS.TEX`
- `tabsenu.gob_TABLE_NEWS.TAB`
- `tabsenu.gob_TABLE_S0.INF` ... `tabsenu.gob_TABLE_S15.INF`
- `tabsenu.gob_TABLE_S0.MAP` ... `tabsenu.gob_TABLE_S15.MAP`
- `tabsenu.gob_TABLE_S0.SCN` ... `tabsenu.gob_TABLE_S15.SCN`
- Additional small scenario-associated table blobs (e.g. `tabsenu.gob_TABLE_S9`, `..._S10`, etc.)

## Content characterization
- `*.INF`: human-readable scenario intro/difficulty text.
- `NEWS.TEX`: human-readable newspaper/event templates.
- `*.MAP`: binary map/province/tile-related data.
- `*.SCN`: binary-ish scenario state/config data (contains markers like `tech`).
- `NEWS.TAB`: index/metadata-style table (not plain text by itself).

## Deeper structure pass (2026-02-16)

Repro script:
- `uv run impk extract_tabsenu_command_summary`

### `NEWS.TAB` (decoded)
- Size: `8640` bytes = `360` records x `24` bytes.
- Endianness/layout: big-endian `6 x int32` per record.
- Field behavior (code/data-confirmed):
  - `col0`: event code (signed).
  - `col1`: title start offset in `NEWS.TEX`.
  - `col2`: title span (includes terminating `NUL`).
  - `col3`: title/body split marker (`col1 + col2` for all records).
  - `col4`: span to next title start measured from `col3`.
  - `col5`: constant `200` (all records).
- Practical effect: `NEWS.TAB` is a compact index into `NEWS.TEX`, not standalone text.

### `S*.SCN` (binary command stream)
- Binary records are tag-driven (4-char command prefix + binary payload).
- Strongly confirmed fixed-width record families:
  - `tech`: `12` bytes (`tag + be32 nation + be32 techId`).
  - `army/rela/ware/capa/emba`: predominantly `16` bytes.
  - `port/rail`: predominantly `8` bytes.
  - `civi/tran/deve/cash`: predominantly `12` bytes.
  - `ship/labo`: predominantly `20` bytes.
- Tag counts closely match corresponding plaintext `tabsenu.gob_TABLE_S9..S15` command files.

### `S9..S15` (no extension) files
- These are plaintext command scripts (CR-delimited), not binary blobs.
- Example directives: `tech`, `zone`, `army`, `emba`, `capa`, `rail`, `port`, `civi`.
- They appear to be source-like companions for binary `.SCN` scenario command data.

### `S*.MAP` (binary map stream)
- All MAP blobs are exactly `309312` bytes.
- Strong structural signal for fixed record stride:
  - `309312 / 36 = 8592` records (exact).
  - high repeated-pattern consistency and high zero-tail incidence at record tail.
- Current conclusion: `.MAP` is structured binary tile/province record data with 36-byte records (field semantics still pending).

### `TABLE_DATA/001..004.TAB`
- Four compact binary tables (`450` bytes each), byte domain `0..4`.
- Value histograms:
  - `001`: `{0:312, 1:23, 3:99, 4:16}`
  - `002`: `{0:282, 1:147, 2:18, 4:3}`
  - `003`: `{0:331, 1:93, 4:26}`
  - `004`: `{0:342, 1:49, 4:59}`
- Plausible matrix interpretations include `30x15` and `25x18`; both fit `450` cells.

## Practical RE use
- Use `tabsenu.gob` to study scenario definitions, map/scenario setup, and news text mechanics.
- Use `STR#ENU.GOB` for UI/dialog/civilian action labels and in-game string IDs.
