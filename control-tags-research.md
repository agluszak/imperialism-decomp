# Control Tags Research (Batch 197, 2026-02-21)

## Method
- Added reusable extractor: `new_scripts/extract_control_tag_usage.py`.
- Ran full-program scan and saved:
  - `tmp_decomp/batch197b_control_tag_usage_detail.csv` (2,744 function-tag rows)
  - `tmp_decomp/batch197b_control_tag_usage_summary.csv` (743 unique 4-char tags)
- Important byte-order note:
  - `tag_le` is immediate byte order in code (e.g. `aert`).
  - `tag_be` is human-readable order (e.g. `trea`).

## High-Signal Command/Control Tags
- `okay` (`yako`): 61 functions / 113 hits
- `cncl` (`lcnc`): 28 / 52
- `acce` (`ecca`): 12 / 15
- `reje` (`ejer`): 10 / 14
- `next` (`txen`): 12 / 14
- `back` (`kcab`): 10 / 14
- `left` (`tfel`): 11 / 98
- `rght` (`thgr`): 13 / 100
- `bar ` (` rab`): 13 / 73
- `move` (`evom`): 14 / 46
- `card` (`drac`): 7 / 38
- `offr` (`rffo`): 9 / 43
- `trea` (`aert`): 20 / 23
- `trad` (`dart`): 13 / 20
- `tran` (`nart`): 13 / 16
- `dipl` (`lpid`): 11 / 14

## Commodity/Metric Tag Family
- `food` (`doof`), `popu` (`upop`), `prof` (`forp`), `powe` (`ewop`), `rail` (`liar`)
- Additional commodity variants seen in production lanes: `grai` (`iarg`), `prod` (`dorp`), `nmbr` (`rbmn`)
- Core function anchors:
  - `SelectTradeCommodityPresetBySummaryTagAndInitControls` (`0x005897b0`)
  - `SelectTradeSummaryMetricByTagAndUpdateBarValues` (`0x0058a020`)
  - `UpdateCityProductionDialogCommodityValueControls` (`0x004bc0b0`)
  - `UpdateTradeSummaryMetricControlsFromRecord` (`0x005866b0`)

## Core UI Meta Tags (broad, lower dehardcoding value)
- `main`, `tool`, `curs`, `pict`, `stat`, `name`, `view`, `base`, `text`
- These are ubiquitous in many dialog/resource constructors and are not good direct semantic anchors by themselves.

## Newly Applied Low-Hanging Renames From Tag Evidence
- `0x004f2e00` -> `HandleDialogEvent10BackOkayAndForward`
- `0x004f3050` -> `HandleDialogEvent14ActionTagsAndEvent10BackOkay`
- `0x004f3710` -> `HandleDialogEvent14TranTreaAndEvent10BackOkay`
- `0x004f9350` -> `HandleDialogAcceptRejectShortcutAndQueueUiEvent`
- `0x005bf860` -> `HandleDialogAcceptRejectShortcutAndQueueUiEventAlt`

Signatures updated in:
- `tmp_decomp/signature_batch197c_control_tag_handlers.csv`

## High-Value Unresolved Hotspots (from command-tag clustering)
- `0x0041b6d0` `Cluster_UiControlA4A8_1C8_1E4_0041b6d0`
  - very dense tag mix: `bar/cncl/food/grai/left/move/nmbr/okay/popu/powe/prod/prof/rail/rght`
  - likely a major trade/production control tree constructor
- `0x00427360` `Cluster_UiControlA4A8_1C8_00427360`
  - tag mix: `city/curs/dipl/grai/powe/prod/prof/tool/trad/tran/trea`
  - likely event/dialog resource builder bridging city-trade-diplomacy lanes
- `0x0045e0b0` `Cluster_UiControlA4A8_1C8_30_0045e0b0`
  - tag mix includes `city/curs/dipl/okay/tool/trad/tran/trea`
- `0x004538a0` `Cluster_UiControlA4A8_1C8_004538a0`
  - command-heavy with `cncl/load/quit/send/okay/curs/tool`

## Next Suggested Control-Tag Steps
1. Build dedicated extractor mode for a selected function set (only unresolved `FUN_`/`Cluster_*Hint_*`) to reduce noise.
2. Decode tag families by dialog class (trade screen vs diplomacy dialogs vs map-order/tactical toolbars).
3. Rename the four hotspot constructors above only after one stronger anchor each (caller or event-code gate), not by tag frequency alone.
