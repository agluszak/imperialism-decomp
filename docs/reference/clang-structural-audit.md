# Clang structural audit

Reviewed triage of the structural clang-tidy/analyzer findings over manually owned
`include/game` + `src/game` source (bead `imperialism-decomp-8mo.24`).

- Date: 2026-07-23
- Input: 103 unique diagnostics from `readability-suspicious-call-argument`,
  `bugprone-casting-through-void`, `bugprone-branch-clone`,
  `bugprone-assignment-in-if-condition`, `clang-analyzer-deadcode.DeadStores`,
  `misc-redundant-expression`, `bugprone-sizeof-expression`,
  `bugprone-macro-parentheses`, `bugprone-implicit-widening-of-multiplication-result`.
- Method: every finding was read in source; the containing function's `// FUNCTION:`
  marker was resolved against `config/baselines/reccmp_progress_baseline.functions.csv`
  (match >= 95% treated as byte-faithful shorthand for class A); callee declarations
  were checked for every suspicious-call-argument site. No Ghidra sessions were run;
  ambiguous below-95% suspects went to the C shortlist instead of being edited.
- Status: advisory record. These checks stay advisory; see the ratchet recommendation.

## Classification key

- **A — faithful decomp shape.** Mirrors the original binary (or is codegen-neutral
  scaffolding of the transcription); must not be "fixed" cosmetically.
- **B — benign-but-improvable modeling.** Correct behavior, but the type-modeling or
  naming debt it exposes should be dissolved by later class/name recovery. Not
  rewritten in this pass.
- **C — candidate real defect.** Needs listing verification before any edit.
- **D — false positive.** The heuristic misfires on this codebase's idioms.

## Summary

- Findings: 103
- Class A: 50
- Class B: 29
- Class C: 1
- Class D: 23

## Findings

Rows sharing one root cause are grouped. Percentages are the containing function's
baseline match at audit time.

| Source | Check | Class | Rationale |
| --- | --- | --- | --- |
| `src/game/CDib.cpp:65,113,272,324,405`; `src/game/CDibPal.cpp:139,143,199,211` | casting-through-void | A | Variable-length Win32 structs (`BITMAPINFO`, `LOGPALETTE`) built inside `new unsigned char[n]` buffers, exactly as the original allocates them; the `static_cast` void-hop is the sanctioned spelling (no new `reinterpret_cast`). `CDib::BuildPaletteFromRgbQuadBuffer`/`Release` are at 100%. |
| `src/game/TDiplomacyMgr.cpp:1684,1700`; `src/game/TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp:243,455` | casting-through-void | A | Same idiom for the variable-length `TurnEvent2SyncPacket` network buffer (alloc as byte array, use as packet, `delete[]` as bytes). |
| `src/game/TTacticalBattleView.cpp:1201` | casting-through-void | B | Commented genuine pun: `TOneTimeAnimation` is CObject-rooted, not `TAnimation`-derived, yet enters the heterogeneous UI transient registry. Guardrail fix: retype `AddObjectToUiTransientRegistry` to take an opaque `void*`/`CObject*` so call sites convert implicitly. |
| `src/game/TViewMgr.cpp:1008,1394` | casting-through-void | B | `TControl*` -> `TCouncilView*` sibling pun on the `ResolveControlByTag(kControlTagMain)` result. Real fix is modeling the main-panel control's concrete class (TView/TControl 184-slot reconstruction); until then the pun is confined to these two sites. |
| `src/game/TTraderAmtBar.cpp:102` | casting-through-void | B | Redundant `reinterpret_cast<TView*>(reinterpret_cast<void*>(...))` chain on an already-`TView*`-typed `ownerContext`. Codegen-neutral; dissolve the cast chain on next touch per the no-new-reinterpret-casts rule (TAmtBar/TradeControl interim-ratchet area). |
| `src/game/TArmyPlayer.cpp:692,726,728,740,1724` | branch-clone | A | Tactical-cursor/AI decision chains where distinct game conditions select the same mode value; the bodies carry shape comments ("branchless in the original", threat/entrench fallbacks). Separate compares exist in the listing; folding them would change branch layout. 1724 is at 94.2%. |
| `src/game/TDefenseMinister.cpp:195` | branch-clone | A | Artillery and light-artillery unit kinds route to the same bucket via two distinct enum compares — game semantics, matching compare chain. |
| `src/game/TDiplomacyMapView.cpp:570` | branch-clone | A | `Draw` mode-dispatch chain; distinct `interactionModeAt94` codes share a renderer. Function also documents a dead `CString` local kept for EH shape. |
| `src/game/TMapMaker.cpp:181` | branch-clone | A | Retry-attempt flag set to 1 by two distinct validation failures — transcribed control flow of the map-generation attempt loop. |
| `src/game/TMapMgr.cpp:2684,2766` | branch-clone | A | Neighbor-tile scans where "own nation" and "at war with owner" (resp. several resource-type groups) produce the same store; distinct predicates exist in the listing. |
| `src/game/TNavyBattle.cpp:41,47` | branch-clone | A | Deployment row-band clamp; both out-of-band sides clear `canDeploy`. Function is at 100% — byte-faithful. |
| `src/game/TNavyMgr.cpp:917,1609` | branch-clone | A | `proceed`/`queueable` predicate chains with several zero branches, mirroring short-circuit compare sequences. |
| `src/game/TViewMgr.cpp:2618` | branch-clone | A | Localized-string dispatch chain over session-role/action tags; two tags legitimately load the same string index. 85.0%. |
| `src/game/ui_text_label_helpers.cpp:37` | branch-clone | A | Switch over UI color tokens: two distinct case IDs map to `PALETTEINDEX(1)`. Case set is data from the binary; merging cases would reorder the switch. |
| `src/game/TTacArmyView.cpp:676` | branch-clone | **C — CONFIRMED, FIXED** | Listing 0x5ac10f/0x5ac118: original pushes `0x33` (threat) / `0x34` (no threat) to `SetForeColor`, and `0x13` (not 0) to `SetQuickDrawFillColorFromPaletteIndex` in the guard branch. Port passed 0 everywhere. Fixed 2026-07-23. |
| `src/game/TAutoGreatPower.cpp:1201`; `src/game/TMacViewMgr.cpp:840,841,845,846`; `src/game/TMapMaker.cpp:513,544,553,564`; `src/game/TMapMgr.cpp:4270`; `src/game/TNavyMgr.cpp:654`; `src/game/TTechMgr.cpp:163` | assignment-in-if | A | Comma-assignment inside short-circuit conditions (`(x = load, x < k)` / LCG advance-and-test / list-cursor advance). This is the transcribed listing shape: the side effect must occur only when the earlier terms pass. Rewriting to statement form changes branch structure. |
| `src/game/ImperialismApp.cpp:110` | DeadStores | A | `hFinal = hProduct` init overwritten on both paths; mirrors the original's register flow through the registry-key fallback chain. Compiler discards the dead store — codegen-neutral. |
| `src/game/TMapMgr.cpp:729,764`; `src/game/TMinor.cpp:601` | DeadStores | A | Locals (`result`, `rolledPredicate`) seeded to document the original's EAX/register value before a rewrite in every live path — transcription scaffolding, codegen-neutral. |
| `src/game/TGreatPower.cpp:2392,2841,3122,4059,4075` | DeadStores | B | `TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;` (and one `TViewMgr` twin) documents the original's cached global load, but the following calls re-read the global instead of using the local. Improvement: route the subsequent dispatches through the local — that is the shape that reproduces a single global load and is a plausible score lever for these 40-49% bodies. |
| `src/game/TCountry.cpp:481`; `src/game/TGreatPower.cpp:4048` | redundant-expression | A | `policyCode == 500 \|\| policyCode != 200` — the first term is logically subsumed, but both compares exist as separate branches in the original (same function ported twice at 0x4d7dd0/0x4e2330). Simplifying drops a compare. |
| `src/game/TGreatPower.cpp:3119` | redundant-expression | A | `proposalCount != 0 && proposalCount > 0` — the original emits a `jz` then a signed `jg`; keep both tests. |
| `src/game/TTacticalBattle.cpp:2376` | redundant-expression | A | `deployMark8 >= 2 && deployMark8 > 1` — already comment-documented ("two consecutive compares... kept literally"); function at 100%. |
| `src/game/TAutoGreatPower.cpp:516,522,524,528,530,545,593`; `src/game/TGreatPower.cpp:3152,3155,3908`; `src/game/TDiplomacyMgr.cpp:916`; `src/game/TDefendProvinceMission.cpp:142`; `src/game/TMinor.cpp:997`; `src/game/TOffersPanelView.cpp:187,201,214,228` | suspicious-call-argument | D | Symmetric nation-pair APIs (`IsNationPairAtWar`, army/navy score ratios, `QueueWarTransitionAndNotifyThirdPartyIfNeeded`, `DispatchOfferPrompt`) called with roles deliberately crossed (evaluating the *other* side, notifying third parties). The heuristic keys on our recovered parameter names, not semantics; containing functions sit at 81-92% with matching call sequences. |
| `src/game/TCivMgr.cpp:497,521`; `src/game/THelpMgr.cpp:295,314,326,341` | suspicious-call-argument | B | Every caller passes `(titleText, formattedText)` into `TViewMgr::ModalMessage(long, CString formatText, CString message, ...)`. Order is consistent codebase-wide; the *callee* parameter names (`formatText`) are the debt — rename to title/message on next `TViewMgr.h` touch to silence the heuristic. |
| `src/game/TForeignMinister.cpp:348,371`; `src/game/TForeignMinisterPersonalities.cpp:191,203,398,404,615,707,813,949,953` | suspicious-call-argument | B | The `ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode)` override family still carries placeholder names; forwarding them into `TTradeMgr::DispatchProposalAmountSlot60`'s named params trips the heuristic 11 times. All personalities forward identically, so this is one signature-naming defect: recover real names on the base virtual (nation slot / amount / context) and the whole group disappears. |
| `src/game/TMapDialog.cpp:555,1892`; `src/game/TWorldView.cpp:215` | suspicious-call-argument | B | `ConvertPoint(const CPoint&, short& outColumn, short& outRow, short& band)` out-params vs caller locals named in the opposite order. Each caller is internally consistent with the map arithmetic (`tileIndex = row * 0x6c + column`), so codegen is unaffected, but the row/col labels across the ConvertPoint family and the TWorldView locals disagree and should be unified in one naming pass. |
| `src/game/TMapMaker.cpp:1446` | suspicious-call-argument | A | `MapGenPassSlot1E` is at 100% — the argument order is byte-verified; only the `class1/class3` local labels drift from the callee's numbering. |
| `src/game/TTEView.cpp:27` | suspicious-call-argument | D | Caller and callee use `layoutParamN` placeholder numbering offset by one; pure name artifact of forwarded opaque layout ints. |
| `include/game/stretch.h:63,65` | sizeof-expression | D | `sizeof(T)` in the shared `stretch<T>` growth helper; instantiations with pointer element types make clang see `sizeof(A*)`, but the element size is exactly what is intended. |
| `src/game/TAutoResolutionDialog.cpp:10`; `src/game/TGreatPower.cpp:83` | macro-parentheses | D | `TG_LAYOUT_ASSERT(name, expr)` expands `name` as a typedef identifier in an array declarator — it cannot be parenthesized. C++98 static-assert idiom. |
| `src/game/ImperialismApp.cpp:742` | implicit-widening | D | `QuadPart / (1024UL * 1024UL)` — the flagged multiplication is a compile-time constant that cannot overflow before widening. |

## C shortlist (needs listing verification)

| Source | Function | Match | Suspicion |
| --- | --- | --- | --- |
| `src/game/TTacArmyView.cpp:676` | `TTacArmyView::DrawTacticalTileInClipRect` (0x5aa900) | 22.5% | RESOLVED 2026-07-23: real transcription bug, confirmed and fixed — original pushes 0x33/0x34 per threat level and 0x13 for the fill-color branch (listing 0x5ac0ec-0x5ac11c); the port passed 0 in all three sites. |

## Ratchet recommendation

No check category is at zero, so a zero-baseline "fully eradicated" gate is not
available for any of them. Two distinct regimes emerged instead:

- **Do not gate** `bugprone-branch-clone`, `bugprone-assignment-in-if-condition`,
  `deadcode.DeadStores`, `misc-redundant-expression`, `bugprone-casting-through-void`,
  and `readability-suspicious-call-argument`: their findings are dominated by class A
  faithful decomp shapes (plus naming debt), and the counts will legitimately *grow*
  as more of the binary is ported. A count ratchet here would invite gate-chasing
  rewrites of intentional shapes.
- **Frozen-count ratchet is viable** for `bugprone-sizeof-expression` (2),
  `bugprone-macro-parentheses` (2), and
  `bugprone-implicit-widening-of-multiplication-result` (1): every current finding is
  a class D false positive confined to fixed, reviewed sites (the `stretch<T>` helper,
  the `TG_LAYOUT_ASSERT` macro, one constant division). A gate that fails only on a
  *new* site for these three checks would catch real sizeof/macro/overflow bugs at
  near-zero noise. Adopt only if a cheap clang-tidy invocation lands in CI; otherwise
  keep all nine checks advisory and re-run this audit opportunistically.
