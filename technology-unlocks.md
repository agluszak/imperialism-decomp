# Imperialism 1 Technology Unlock Notes (University/Civilians)

Source page: https://imperialism.fandom.com/wiki/Technology_(Imp1)
Extracted: 2026-02-15

## Relevant Civilian-Unlock Technologies

| Tech | Approx year | Cost | Prerequisites | Effect relevant to University civilians |
|---|---|---:|---|---|
| Iron Railroad Bridge | 1821-24 | 1,500 | None | Enables **Forester** unit (hardwood forest level 1 improvements). |
| Feed Grasses | 1821-24 | 1,500 | None | Enables **Rancher** unit (wool/livestock level 1 improvements). |
| Oil Drilling | 1856-58 | 25,000 | None (per wiki table) | Enables **Driller** unit and oil production/prospecting in desert/tundra/swamp. |

## Baseline Availability Notes

- `Miner`, `Prospector`, `Farmer`, and `Engineer` are treated as baseline-available in current University UI investigation context.
- Forester/Rancher/Driller should be gated by technology-state checks in University dialog code.

## Implications for Code Tracing

When tracing university unlock checks, prioritize detection of comparisons/bit tests against technology-state values associated with:
- Iron Railroad Bridge (Forester)
- Feed Grasses (Rancher)
- Oil Drilling (Driller)

Likely code locations:
- University row construction and refresh routines around `0x00474ac5..0x004784ce`
- University apply/commit handlers that populate row enabled/disabled state
