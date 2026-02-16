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
- `string_id = block * 16 + index_in_block`
- `index_in_block` is `0..15`

Each entry layout in binary:
- `uint16 length` (UTF-16 code units)
- then `length * 2` bytes of UTF-16LE text
- `length = 0` means empty slot

## Produced canonical index

Generated full TSV index:
- `/home/andrzej.gluszak/code/personal/imperialism_knowledge/strenu-strings.tsv`
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
  /home/andrzej.gluszak/code/personal/imperialism_knowledge/strenu-strings.tsv
```

## Confirmed anchor strings from STR#ENU.GOB
- `64662` (`block 4041 idx 6`): `Construction Options`
- `18988` (`block 1186 idx 12`): `Civilian Report`
- `18989` (`block 1186 idx 13`): `Rescind Orders`
- `18990` (`block 1186 idx 14`): `Confirm Orders`
- `18986` (`block 1186 idx 10`): `Time to completion: [1:number] months`
- `23477` (`block 1467 idx 5`): `Miners open mines for minerals .`
- `23478` (`block 1467 idx 6`): `Prospectors search for minerals in hills and mountains.`
