# Cursor Semantics and EXE Resource Mapping

Date: 2026-02-16
Source of semantics: user-provided in-session identifications.
Resource source: `Imperialism.exe` (`RT_CURSOR` type `1`, `RT_GROUP_CURSOR` type `12`).

Notes:
- `RT_CURSOR` entries are raw image blobs keyed by `raw_cursor_id`.
- `RT_GROUP_CURSOR` entries are indirection records used by `LoadCursorA`.
- Group cursor `1013` contains two raw cursor images (`20` and `21`).

## Terrain / Orders / Military

| Raw Cursor ID | Group Cursor ID | Name | Meaning |
|---:|---:|---|---|
| 8 | 1001 | Prospecting Cursor | Hover over prospectable tile |
| 9 | 1002 | Build Railway Horizontal Cursor | Build horizontal railway |
| 10 | 1003 | Build Improvement Cursor | Build improvement |
| 11 | 1004 | Move Civilian Cursor | Move civilian |
| 12 | 1005 | Land Military Cursor A | Land military related (variant A) |
| 13 | 1006 | Land Military Cursor B | Land military related (variant B) |
| 14 | 1007 | Land Military Cursor C | Land military related (variant C) |
| 16 | 1009 | Select Navy Cursor | Select navy |
| 18 | 1011 | Busy Civilian Rescind Orders Cursor | Busy civilian; click to rescind orders |
| 19 | 1012 | Navy Cursor A | Navy related (variant A) |
| 20 | 1013 | Navy Cursor B | Navy related (variant B) |
| 21 | 1013 | Navy Cursor C | Navy related (variant C) |
| 22 | 1014 | Navy Cursor D | Navy related (variant D) |
| 23 | 1015 | Navy Cursor E | Navy related (variant E) |
| 24 | 1016 | Navy Cursor F | Navy related (variant F) |
| 26 | 1018 | Build Railway Diagonal Slash Cursor | Build rails in `/` diagonal |
| 27 | 1019 | Build Railway Diagonal Backslash Cursor | Build rails in `\\` diagonal |
| 32 | 1025 | Developer Buy Tile Cursor | Developer buy tile cursor |
| 36 | 1000 | Select Army Cursor | Select army |

## Tactical Battle

| Raw Cursor ID | Group Cursor ID | Name | Meaning |
|---:|---:|---|---|
| 28 | 1020 | Tactical Shoot Cursor | Tactical battle shoot |
| 29 | 1021 | Tactical Melee Cursor | Tactical battle hand-to-hand |
| 30 | 1022 | Sapper Cursor A | Sapper related (variant A) |
| 31 | 1023 | Sapper Cursor B | Sapper related (variant B) |
| 33 | 1024 | Tactical Cannot Shoot Cursor | "Can't shoot" cursor |
| 34 | 1026 | Tactical AI Moving Cursor | Shown when AI is moving in tactical battle |

## Diplomacy (37-59)

| Raw Cursor ID | Group Cursor ID | Name | Meaning |
|---:|---:|---|---|
| 37 | 1028 | Diplomacy Peace Cursor | Peace |
| 38 | 1029 | Diplomacy War Cursor | War |
| 39 | 1030 | Diplomacy Non-Aggression Pact Cursor | Non-aggression pact |
| 40 | 1031 | Diplomacy Alliance Cursor | Alliance |
| 41 | 1032 | Diplomacy Empire Colony Cursor | Join empire / become colony |
| 42 | 1033 | Diplomacy Subsidy 5 Percent Cursor | Subsidy 5% |
| 43 | 1034 | Diplomacy Subsidy 10 Percent Cursor | Subsidy 10% |
| 44 | 1035 | Diplomacy Subsidy 25 Percent Cursor | Subsidy 25% |
| 45 | 1036 | Diplomacy Subsidy 50 Percent Cursor | Subsidy 50% |
| 46 | 1037 | Diplomacy Subsidy 75 Percent Cursor | Subsidy 75% |
| 47 | 1038 | Diplomacy Subsidy 100 Percent Cursor | Subsidy 100% |
| 48 | 1039 | Diplomacy Boycott All Trade Cursor | Boycott All Trade |
| 49 | 1040 | Diplomacy Colony Boycott Cursor | Direct colonies to boycott |
| 50 | 1041 | Diplomacy One-Time Grant 1K Cursor | One-time grant 1K |
| 51 | 1042 | Diplomacy One-Time Grant 3K Cursor | One-time grant 3K |
| 52 | 1043 | Diplomacy One-Time Grant 5K Cursor | One-time grant 5K |
| 53 | 1044 | Diplomacy One-Time Grant 10K Cursor | One-time grant 10K |
| 54 | 1045 | Diplomacy Per-Turn Grant 1K Cursor | Per-turn grant 1K |
| 55 | 1046 | Diplomacy Per-Turn Grant 3K Cursor | Per-turn grant 3K |
| 56 | 1047 | Diplomacy Per-Turn Grant 5K Cursor | Per-turn grant 5K |
| 57 | 1048 | Diplomacy Per-Turn Grant 10K Cursor | Per-turn grant 10K |
| 58 | 1049 | Diplomacy Build Trade Consulate Cursor | Build Trade Consulate |
| 59 | 1050 | Diplomacy Build Embassy Cursor | Build Embassy |
