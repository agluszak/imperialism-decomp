# TODO / follow-ups

## `IsSelected` (slot 0x73) per-branch arity reconciliation

Slot 0x73 (`IsSelected`, offset 0x1cc) is **not a single shared virtual** — it is
introduced independently by several `TPicture` subclasses, each with its **own arity**.
Batch-disassembling the bodies (via `tools.ghidra.listing_one`, classify by `RET imm`)
gave:

| Class | Body addr | `RET` | Arity |
|---|---|---|---|
| TToggleButton | 0x571330 | tail-JMP | 0-arg ✅ fixed |
| T2PictToggleButton | 0x5849b0 | RET 0 | 0-arg ✅ fixed |
| TPictureButton | 0x5708c0 | RET 0 | 0-arg — **paradox, see below** |
| TTransportPicture | 0x5921c0 | RET 0 | 0-arg — pending |
| TUpDownPictureButton | 0x571690 | tail-JMP | TBD (need caller evidence) |
| TCivReport | 0x590cb0 | RET 0x4 | 1-arg — pending |
| TCombatReportView | 0x58c950 | RET 0x4 | 1-arg — pending |
| TArmyInfoView / TArmyPlacard / THQButton / TPlacard | … | RET 0x8 | 2-arg (already correct) |

**Done:** TToggleButton branch (TToggleButton + T2PictToggleButton override; TBoycottButton
and TPictureRadioButton inherit) changed from the wrong `IsSelected(short=-1, bool=true)` to
the real 0-arg `IsSelected()`.

**Remaining work — must verify each branch's call sites against its body before flipping
(unlike TToggleButton, these branches have real arg-passing callers):**

- **TPictureButton branch paradox:** body `0x5708c0` is `RET 0` (0-arg) yet
  `src/game/TPictureButton.cpp:29` calls `this->IsSelected(-1, true)` (2-arg). Disassemble
  the line-29 call site (and the other inheritors: TCloseButton, TOnOffRadioButton,
  TAlwaysPictureButton, T2PictureButton, TScrollerButton, TClosePicture) to decide the real
  arity, then fix the introducing class + all overrides + call sites together.
- **TCivReport / TCombatReportView:** bodies are `RET 0x4` (1-arg) but declared 2-arg —
  change to `IsSelected(<one arg>)` and fix callers.
- **TUpDownPictureButton branch** (+ TCivilianButton, TTextPictureButton, TRadioPictureButton,
  TMadnessButton, TCzechBox): body `0x571690` is a tail-JMP (arity ambiguous from the body) —
  determine arity from call sites.

Note: the bodies that are pure tail-`JMP` forwarders (e.g. `0x571330`) are codegen-capped by
call-vs-jmp regardless of arity; the arity fix's value is in the **callers** (it removes the
spurious default-arg pushes), not the 8-byte forwarder body itself.
