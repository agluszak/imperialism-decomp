# Imperialism 1 Technology Unlock Notes (University/Civilians)

Source page: https://imperialism.fandom.com/wiki/Technology_(Imp1)
Extracted: 2026-02-15

## Relevant Civilian-Unlock Technologies

| Tech | Tech ID | Approx year | Cost | Prerequisites | Effect relevant to University civilians |
|---|---:|---|---:|---|---|
| Iron Railroad Bridge | 6 | 1821-24 | 1,500 | None | Enables **Forester** unit (university category 3). |
| Feed Grasses | 7 | 1821-24 | 1,500 | None | Enables **Rancher** unit (university category 5). |
| Oil Drilling | 0x13 | 1856-58 | 25,000 | None (per wiki table) | Enables **Driller** unit (university category 8) and oil production/prospecting. |

## Baseline Availability Notes

- `Miner`, `Prospector`, `Farmer`, and `Engineer` are treated as baseline-available in current University UI investigation context.
- `TTechMgr::HandleAbilityUnlock` writes the per-nation availability bytes for
  Forester/Rancher/Driller, and `TUniversityView::DoStartup` reads those bytes to enable or
  disable the corresponding rows.

## Implications for Code Tracing

When tracing university unlock checks, prioritize detection of comparisons/bit tests against technology-state values associated with:
- Iron Railroad Bridge (Forester)
- Feed Grasses (Rancher)
- Oil Drilling (Driller)

Confirmed code locations:
- `TTechMgr::HandleAbilityUnlock` at `0x005afd00`: tech IDs 6, 7, and 0x13 write categories
  3, 5, and 8 respectively in `universityRecruitmentAvailabilityByNation467`.
- `TUniversityView::DoStartup` at `0x004cace0`: reads the active nation's nine-byte row and
  enables/disables the `civ*` and `clu*` controls.
