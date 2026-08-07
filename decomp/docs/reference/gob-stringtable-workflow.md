# Imperialism GOB / STR#ENU Workflow

## Data locations
- Game data folder:
  - `/home/andrzej.gluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Data`
- Extractor script:
  - `/home/andrzej.gluszak/code/personal/rust-imperialism/extract_data.py`
- Existing extracted assets:
  - `/home/andrzej.gluszak/code/personal/rust-imperialism/assets/extracted`

## How `extract_data.py` navigates GOB files

The script uses `wrestool` on each `.gob/.GOB`:
1. `wrestool -l <gob>` to enumerate resources.
2. Parses entries like `--type=... --name=... --language=...`.
3. Extracts by type with `wrestool -x`.
4. Uses `--raw` for resource types that are not normally decoded:
   - `WAVE`, `TABLE`, `6` (`STRINGTABLE`).
5. Writes outputs into type-specific folders:
   - bitmaps -> `bitmaps/*.BMP`
   - waves -> `wav/*.wav`
   - stringtables -> `strings/strtbl-<name>.bin`

For stringtables it also runs:
- `strings -el strtbl-<name>.bin` to create a quick skim `.txt` file.

## Win32 STRINGTABLE decoding details

Each `strtbl-<block>.bin` file is one STRINGTABLE block with 16 entries.

Entry ID formula:
- runtime `LoadStringA` ID: `string_id = (block - 1) * 16 + index_in_block`
- the historical `strenu-strings.tsv` generator used `block * 16 + index_in_block`,
  so its committed `id` column is 16 higher than the runtime ID; the Mac string
  crosswalk preserves that value as `legacy_tsv_id` and reports the corrected
  `load_string_id`
- `index_in_block` is `0..15`

Each entry layout in binary:
- `uint16 length` (UTF-16 code units)
- then `length * 2` bytes of UTF-16LE text
- `length = 0` means empty slot

## Produced canonical index

Generated full TSV index:
- `docs/reference/strenu-strings.tsv` (sample: `docs/reference/strenu-index-sample.txt`)
- columns: `id`, `block`, `index`, `text`

This is now the fastest way to map in-game/UI text to numeric resource IDs used in code.

## Quick useful commands

Search extracted text skims quickly:
```bash
rg -n "Construction Options|Civilian Report|Rescind Orders|Confirm Orders" \
  /home/andrzej.gluszak/code/personal/rust-imperialism/assets/extracted/strings/*.txt
```

Search canonical ID index:
```bash
rg -n "Construction Options|Civilian Report|Time to completion" \
  docs/reference/strenu-strings.tsv
```

Cross-platform semantic queries:
```bash
just mac-string-search "railroad"
just string-crosswalk 1509 2
just strings-for-function 0x0056f560
```

`string-crosswalk` deliberately lists every resource-file-scoped Mac match when
a group/index collides. `Strings.rsrc` entries additionally use the original
Windows runtime mapping `(group * 100 + index) & 0xffff`; local View-resource
strings are matched against named embedded globals and GOB text by exact or
normalized text. Candidate ties remain visible rather than being asserted as a
single identity.

## Confirmed anchor strings from STR#ENU.GOB
- `64662` (`block 4041 idx 6`): `Construction Options`
- `18988` (`block 1186 idx 12`): `Civilian Report`
- `18989` (`block 1186 idx 13`): `Rescind Orders`
- `18990` (`block 1186 idx 14`): `Confirm Orders`
- `18986` (`block 1186 idx 10`): `Time to completion: [1:number] months`
- `23477` (`block 1467 idx 5`): `Miners open mines for minerals .`
- `23478` (`block 1467 idx 6`): `Prospectors search for minerals in hills and mountains.`
