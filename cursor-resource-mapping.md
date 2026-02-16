# Cursor Resource Mapping (Imperialism.exe)

Date: 2026-02-16

Sources:
- `Data/extracted_cursors_exe/group_cursor/*.cur` (RT_GROUP_CURSOR, type 12)
- `Data/extracted_cursors_exe/cursor/*.cur` (RT_CURSOR, type 1 raw entries)

Notes:
- Group cursor IDs `1000..1053` are the range loaded by `LoadTurnEventCursorTable` (`0x005d5100`).
- Group cursor `1054` and `227` exist in EXE resources but are outside that loop range.

## Group Cursor -> Cursor Entry Mapping

| Group ID | Entry Count | Cursor IDs | Entry Metadata |
|---:|---:|---|---|
| 227 | 1 | `7` | id 7: 32x256 color=64 planes/hx=1 bits/hy=1 grpBytes=308 rawSize=308 |
| 1000 | 1 | `36` | id 36: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1001 | 1 | `8` | id 8: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1002 | 1 | `9` | id 9: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1003 | 1 | `10` | id 10: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1004 | 1 | `11` | id 11: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1005 | 1 | `12` | id 12: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1006 | 1 | `13` | id 13: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1007 | 1 | `14` | id 14: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1008 | 1 | `15` | id 15: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1009 | 1 | `16` | id 16: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1010 | 1 | `17` | id 17: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1011 | 1 | `18` | id 18: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1012 | 1 | `19` | id 19: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1013 | 2 | `20,21` | id 20: 32x256 color=64 planes/hx=1 bits/hy=8 grpBytes=2220 rawSize=2220; id 21: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1014 | 1 | `22` | id 22: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1015 | 1 | `23` | id 23: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1016 | 1 | `24` | id 24: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1017 | 1 | `25` | id 25: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1018 | 1 | `26` | id 26: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1019 | 1 | `27` | id 27: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1020 | 1 | `28` | id 28: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1021 | 1 | `29` | id 29: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1022 | 1 | `30` | id 30: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1023 | 1 | `31` | id 31: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1024 | 1 | `33` | id 33: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1025 | 1 | `32` | id 32: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1026 | 1 | `34` | id 34: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1027 | 1 | `35` | id 35: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1028 | 1 | `37` | id 37: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1029 | 1 | `38` | id 38: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1030 | 1 | `39` | id 39: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1031 | 1 | `40` | id 40: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1032 | 1 | `41` | id 41: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1033 | 1 | `42` | id 42: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1034 | 1 | `43` | id 43: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1035 | 1 | `44` | id 44: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1036 | 1 | `45` | id 45: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1037 | 1 | `46` | id 46: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1038 | 1 | `47` | id 47: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1039 | 1 | `48` | id 48: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1040 | 1 | `49` | id 49: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1041 | 1 | `50` | id 50: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1042 | 1 | `51` | id 51: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1043 | 1 | `52` | id 52: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1044 | 1 | `53` | id 53: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1045 | 1 | `54` | id 54: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1046 | 1 | `55` | id 55: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1047 | 1 | `56` | id 56: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1048 | 1 | `57` | id 57: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1049 | 1 | `58` | id 58: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1050 | 1 | `59` | id 59: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1051 | 1 | `60` | id 60: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1052 | 1 | `61` | id 61: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1053 | 1 | `62` | id 62: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |
| 1054 | 1 | `63` | id 63: 32x256 color=64 planes/hx=1 bits/hy=4 grpBytes=748 rawSize=748 |

## Standalone Cursor Raw Entries (type 1)

- ID range: `7..63`
- Size histogram: `308` bytes: `1` files, `748` bytes: `55` files, `2220` bytes: `1` files

## Other Interesting EXE Resource Types

Resource inventory from `wrestool -l Imperialism.exe`:
- `accelerator`: `1`
- `bitmap`: `5`
- `cursor`: `57`
- `dialog`: `6`
- `group_cursor`: `56`
- `group_icon`: `3`
- `icon`: `6`
- `menu`: `1`
- `string`: `16`
- `toolbar`: `1`
- `version`: `1`

## Semantic Overlay

User-confirmed semantic labels for cursor IDs were captured on 2026-02-16 and saved in:

- `cursor-semantics-exe.md`

That file maps gameplay meaning to both resource IDs:
- raw `RT_CURSOR` IDs (type `1`)
- `RT_GROUP_CURSOR` IDs (type `12`)
