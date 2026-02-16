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
