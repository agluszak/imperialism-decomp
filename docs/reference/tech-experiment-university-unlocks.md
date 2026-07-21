# Tech Experiment: University Unlocks and Scenario Tech Records

Date: 2026-02-16

## Goal
Correlate technology unlock behavior (Forester/Rancher/Driller availability) with on-disk scenario tech records from `tabsenu.gob` and known UI strings from `STR#ENU.GOB`.

## Method
- Parsed `tabsenu.gob_TABLE_S*.SCN` for repeated 12-byte `tech` records: `"tech" + be32 nationIndex + be32 techId`.
- Searched `strenu-strings.tsv` for university/civilian-tech unlock descriptions.
- Cross-checked with manual and wiki page: https://imperialism.fandom.com/wiki/Technology_(Imp1).

## SCN Tech Record Findings
Observed record format is consistent and machine-readable:
`74 65 63 68` (`tech`) then two big-endian uint32 values.

| SCN file | tech records | nations present | techId range |
|---|---:|---|---|
| `tabsenu.gob_TABLE_S0.SCN` | 42 | 0 1 2 3 4 5 6 | 1-6 |
| `tabsenu.gob_TABLE_S1.SCN` | 147 | 0 1 2 3 4 5 6 | 1-21 |
| `tabsenu.gob_TABLE_S12.SCN` | 63 | 0 1 2 3 4 5 6 | 1-9 |
| `tabsenu.gob_TABLE_S13.SCN` | 42 | 0 1 2 3 4 5 6 | 1-6 |
| `tabsenu.gob_TABLE_S14.SCN` | 42 | 0 1 2 3 4 5 6 | 1-6 |
| `tabsenu.gob_TABLE_S3.SCN` | 98 | 0 1 2 3 4 5 6 | 1-14 |
| `tabsenu.gob_TABLE_S9.SCN` | 63 | 0 1 2 3 4 5 6 | 1-9 |

Per-nation ranges (compressed):
- `tabsenu.gob_TABLE_S0.SCN` nation 0: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S0.SCN` nation 1: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S0.SCN` nation 2: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S0.SCN` nation 3: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S0.SCN` nation 4: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S0.SCN` nation 5: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S0.SCN` nation 6: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S1.SCN` nation 0: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S1.SCN` nation 1: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S1.SCN` nation 2: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S1.SCN` nation 3: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S1.SCN` nation 4: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S1.SCN` nation 5: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S1.SCN` nation 6: 21 techs -> 1-21
- `tabsenu.gob_TABLE_S12.SCN` nation 0: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S12.SCN` nation 1: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S12.SCN` nation 2: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S12.SCN` nation 3: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S12.SCN` nation 4: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S12.SCN` nation 5: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S12.SCN` nation 6: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S13.SCN` nation 0: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S13.SCN` nation 1: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S13.SCN` nation 2: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S13.SCN` nation 3: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S13.SCN` nation 4: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S13.SCN` nation 5: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S13.SCN` nation 6: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 0: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 1: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 2: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 3: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 4: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 5: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S14.SCN` nation 6: 6 techs -> 1-6
- `tabsenu.gob_TABLE_S3.SCN` nation 0: 14 techs -> 1-14
- `tabsenu.gob_TABLE_S3.SCN` nation 1: 19 techs -> 1-10, 10-11, 11-12, 12-13, 13-14, 14
- `tabsenu.gob_TABLE_S3.SCN` nation 2: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S3.SCN` nation 3: 14 techs -> 1-14
- `tabsenu.gob_TABLE_S3.SCN` nation 4: 14 techs -> 1-14
- `tabsenu.gob_TABLE_S3.SCN` nation 5: 15 techs -> 1-14, 14
- `tabsenu.gob_TABLE_S3.SCN` nation 6: 13 techs -> 1-13
- `tabsenu.gob_TABLE_S9.SCN` nation 0: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S9.SCN` nation 1: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S9.SCN` nation 2: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S9.SCN` nation 3: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S9.SCN` nation 4: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S9.SCN` nation 5: 9 techs -> 1-9
- `tabsenu.gob_TABLE_S9.SCN` nation 6: 9 techs -> 1-9

## University-Relevant Unlock Strings (from STR#ENU parse)
| String ID | Text |
|---:|---|
| 2344 | Although the first successful internal combustion engine was invented in 1860 by Lenoir, practical applications were not developed until the close of the century.  Diesel patented his engine in 1892, and in 1893 both Karl Benz and Henry Ford built their first motorcars.\n\nPractical oil and gasoline burning internal combustion engines permit the recruiting of Armored and Mechanized regiments and the upgrading of older units to these modern types. Additionally, Drillers may improve Oil wells to Level III, producing six units per turn. |
| 17184 | Feed Grasses |
| 23182 | Allows Engineers to build railroads through swamps. Allows Forester unit and improvement of Timber to Level I |
| 23183 | Allows production of a Rancher and the improvement of Wool farms and Livestock ranches to Level I |
| 23195 | Allows building of a Driller and production of Oil at Level I. Prospect for Oil in Desert and Swamp. Build Refinery and Power Plant. |
| 23204 | Allows recruiting of armored and mechanized regiments and upgrading older units to these modern types. Drillers may improve Oil wells to Level III |

## Working Hypothesis
- `techId` in `.SCN` appears to mark technologies granted at scenario start (by nation).
- University unit availability gates (Forester/Rancher/Driller) are controlled by global researched-tech flags checked by university UI/build-order logic.
- Next Ghidra step: locate university availability function and bind specific bit/ID checks to named techs using `techId` comparisons and string/bitmap anchors (`9926`, `9930`, `9936`).

## 2026-07-13 update (bd imperialism-decomp-1uj.34): availability check located

Located the actual per-row availability check and the icon-to-role binding (both
confirmed from Ghidra disassembly, not guessed):

- **Row build/icon binding** — `BuildUniversityRecruitmentRows` (0x00475f84, 9547
  bytes; symbols.csv currently has no name for this address, but its entry point
  matches the plan doc's cited `0x00475f84` exactly). A prior Ghidra plate comment on
  this function already records the confirmed bindings for the string/bitmap anchors
  cited above: `civ0`->9920 Miner, `civ1`->9922 Prospector, `civ2`->9924 Farmer,
  **`civ3`->9926 Forester**, `civ4`->9928 Engineer, **`civ5`->9930 Rancher**, and
  **`civ8`->9936 Driller** (civ6/civ7 unconfirmed/reserved). This directly matches the
  string-anchor IDs (9926/9930/9936) the bead asked to bind.
- **Per-row availability read** — `TUniversityView::OrphanRetStub_004c6fd0` (0x4cace0,
  slot 0x75, currently declared but unported in `include/game/TUniversityView.h`)
  iterates recruit-row tags `clu0..clu8` (rows 6/7 skipped) and, for each row, reads a
  single capability byte:
  `g_pCityOrderCapabilityState[TTechMgr + 0x467 + nationSlot*9 + rowIndex]`
  (`this + nRecruitControlTag - 0x636c70c9 + nationSlot*9`, where `0x636c7530` is the
  `'clu0'` tag and `0x467` is the row-index-0 base). When the byte is 0 the row takes
  a different (unavailable-looking) control path. This is the actual "university
  availability" gate the bead asks for -- it lives in `TTechMgr` (aka
  `g_pCityOrderCapabilityState`, `0x006A43D8`), not in `TCountry`/`TGreatPower`. The
  9-byte-per-nation table at `TTechMgr+0x467` is not yet declared as a named field in
  `include/game/TTechMgr.h` (it currently ends its explicit fields at
  `militaryCapRows39d` around `+0x39d..+0x46f`, so this array immediately follows/
  overlaps that region and needs its own dedicated field).
- **Global tech-unlock writer (different system, ruled out for civilian rows)** —
  `ApplyCityOrderCapabilityUnlockByTechId(int nTechId)` (0x5afba0, `__thiscall` on
  `g_pCityOrderCapabilityState`) is the real per-tech unlock handler: it sets a
  researched-flag byte at `TTechMgr+0x180+nTechId` (a flat, nation-agnostic bitmask --
  matches the "tech store" shared-race mechanic, see `TTechStorePage`/
  `AreTechItemPrerequisitePairCompleted`) and has explicit `case` arms for techId
  4, 9, 0xb, 0xf, 0x15, 0x16, 0x18, 0x1b that write specific bytes at `+0x1a3..+0x1aa`
  and selector shorts at `+0x1d2`/`+0x1d4`. Traced its callers
  (`TTechMgr::CheckForAdvances` 0x5af980, `ApplyTechUnlockAndQueueNation-
  AbilityNotices` 0x5afb10): confirmed this bitmask is **not** indexed by nation and is
  **not** the same array `OrphanRetStub_004c6fd0` reads -- it does not write
  `TTechMgr+0x467`. The `+0x1a3..+0x1aa` bytes it does write look ship/navy-related
  (two of them are already named `shipCapabilityFlag1a5`/`shipCapabilityFlag1a8` in
  `TTechMgr.h` from a prior session), so this global tech-race system is a *different*
  unlock path from the university civilian rows, not the one gating Forester/Rancher/
  Driller.

**Not yet resolved**: which specific `techId` values (if any -- vs. direct
scenario-start `.SCN` seeding of the `TTechMgr+0x467` per-nation table, per the
"Working Hypothesis" above) flip Forester/Rancher/Driller's `TTechMgr+0x467` bytes.
`InitializeCityOrderCapabilityStateDefaults` (0x5aeff0) seeds that table's bytes to a
fixed `{1,1,0,0,0,0,0,0,0}`-shaped default per nation at scenario start, and no writer
touching `+0x467` at a per-tech-unlock callsite was found in this pass -- the remaining
work is to find whichever save/load or scenario-init path re-seeds this table's
per-row bytes from the `.SCN` `tech` records (or a runtime writer not yet located).
Good next-session anchors: `TTechMgr::InitializeCityOrderCapabilityStateDefaults`
(0x5aeff0), the `.SCN` tech-record loader, and `include/game/TTechMgr.h`'s currently
undeclared `+0x467` region.
