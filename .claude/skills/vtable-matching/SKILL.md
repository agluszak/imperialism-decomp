---
name: vtable-matching
description: Drive `just vtable <Class>` to 100% for the Imperialism decomp — read the reccmp vtable diff, classify each slot mismatch (inherited-base, scalar-deleting-dtor, missing override, stub-in-slot, imported-thunk), and apply the fix. Use when a class's vtable comparison is below 100% or a specific slot points at the wrong function. For reconstructing an unknown layout/inheritance first, use class-recovery; for the raw-vtable source gate, use quality-control.
---

# Vtable matching

Getting `just vtable <Class>` to 100% means every **slot points at the function reccmp
pairs with the original's slot**. This is distinct from *recovering* the layout (that's
`class-recovery`) and from the raw-vtable source gate (`just vtable-gate`, in
`quality-control`). Hard Rules + the calling-convention guardrail are in `AGENTS.md`;
deep tactics in `decomp-loop/heuristics.md` (#4, #7, #8).

**Start from the manifest.** `config/classes/<Class>.yml` already has the resolved
slot table (`generated.slots`: `target`/`kind`/`is_thunk`, in slot order) and the
class+base diff baked into `kind`. Refresh it with `just dump-manifests --only
<Class>`, read the slots there instead of re-deriving by hand, and record the
semantic name / new-vs-reused-base judgment in `curated.slots`. `just gen-class
<Class> --write` keeps the header's generated block (the slot→address→method
skeleton) in sync; `just manifest-gate` fails on drift. See `class-recovery` for
the manifest schema.

## Mechanics you must internalize

1. **Pairing is by `// FUNCTION:` marker source-line**, not by body content. So slot
   correctness only needs the *right function to occupy the slot* — a partial/honest
   body still pairs. Do NOT fake a body to "win" a slot (AGENTS rule 11); promote the
   real function with whatever fidelity you have.
2. **Slot byte-offset = index × 4.** Slot `0x94` = index 37 = the 0x25th introduced
   virtual. A class's own virtuals start after the last inherited slot.
3. **A slot is filled by a real C++ virtual/override in declaration order.** Match the
   original's slot order exactly; reordering members reorders the vtable.
4. **Markers must be ascending by address within a file** or `just decomplint` errors
   `function_out_of_order` (and `just gates` fails). Insert promoted functions at the
   right address position, respecting any `#pragma optimize` region.

## Read the diff

`just vtable [NameSubstring]` → per class: `(orig_addr / recomp_addr) : name`. Red `-`
lines are the orig side, green `+` the recomp side; a slot with both is a mismatch.
`(no orig / …)` on recomp = our function isn't paired to any original (usually a
scalar-deleting-dtor or stub needing a pairing fix).

## Classify every mismatch, then fix

**First: is it inherited?** Run `just vtable <BaseClass>`. If the same slot mismatches
there, fix the BASE — the derived class inherits the fix family-wide. Don't patch it on
the derived class.

| Symptom | Fix |
|---|---|
| **Scalar deleting dtor** (often slot 0x04): recomp `` `scalar deleting destructor' `` shows `no orig` | Pair via SYNTHETIC: set the orig addr's `config/symbols.csv` name to ``Class::`scalar deleting destructor'``, replace any hand-written `*AndMaybeFree` bridge with a `// SYNTHETIC: …` marker. Needs a polymorphic class. See `decomp-loop/heuristics.md` #8 and [[synthetic-scalar-deleting-dtor]]. |
| **Missing override**: orig slot → a class-specific addr, recomp → the inherited base function | Declare an `override` with the base's exact signature/name, give it the real body + `// FUNCTION:` marker at the orig addr. |
| **Stub-in-slot**: recomp slot → an empty provisional virtual, while a real function exists as a stub at the orig addr | Promote: make the virtual method own the stub's address (move the `// FUNCTION:` marker onto the method, write an honest body), then `just sync-ownership` → `just regen-stubs` to drop the stub. |
| **Imported thunk**: orig slot → an ILT `jmp` thunk addr (`0x40xxxx`), recomp → the direct target | reccmp auto-resolves jmp thunks *unless the thunk is annotated as a function*. Un-import it. See below + [[imported-thunks-block-vtable-resolution]]. |
| **Unowned base slot**: recomp slot has `no orig` and a tiny return-0 body matches an orphan stub (`OrphanTiny_ReturnZero_*`) | Claim the orig addr: add the `// FUNCTION:` marker to the base method (only if bodies genuinely match). |

### Un-importing a thunk slot

The orig vtable legitimately stores ILT `jmp rel32` thunk addresses (incremental
linking). reccmp resolves `JMP 0xTARGET` → `0xTARGET` and matches our direct reference —
but only when the thunk address is **not** claimed as a function on our side. To free it:

1. Remove its row from `config/symbols.csv` (stubgen sources addresses here, so its
   autogen stub stops regenerating).
2. Delete any hand-written fake body + marker (e.g. in `src/game/thunks.cpp`). Fake
   no-op/jmp bodies for ILT thunks are forbidden regardless.
3. Repoint any callsite that references the thunk symbol by name so it links without the
   stub — for a thunk to a base method, a qualified non-virtual call works:
   `reinterpret_cast<Base*>(this)->Base::Method(args)`.
4. `tools/workflow/prune_ilt_thunks.py` automates step 1 for unclaimed/unreferenced
   thunks in the ILT region.

## Verify loop

After each fix: `just sync-ownership` → `just regen-stubs` → `just build` → `just detect`
→ `just vtable <Class>` (expect `100% match`). Then `just gates` (marker hygiene +
decomplint ordering) and `just format-check <touched paths>`. If you changed a **base**
class, re-run `just vtable` on a couple of derived classes and `just stats` — base edits
touch the whole family. Build the binary before trusting the diff; the
comparison reads the freshly built `Imperialism.exe`/`.pdb`.

## Guardrails

- Fix inherited mismatches at the base, never per-derived-class.
- Slot correctness is body-independent — promote real functions with honest bodies, do
  not fabricate code to chase the slot (AGENTS rules 6 & 11).
- Keep `config/symbols.csv` edits surgical; it is regenerated by `just sync-ghidra`, so
  durable renames belong in Ghidra / `config/function_name_overrides.csv`.
- Model real virtuals/overrides, not `VCall_*` facades or `__thiscall` reinterpret_casts,
  when occupying a slot (the calling-convention guardrail in `AGENTS.md`).

## Troubleshooting & Common Gotchas

1. **Linker Errors for External/QuickDraw Helpers**: When promoting functions, you may encounter linkage failures (e.g., `unresolved external symbol`) for external helpers (like `IsPointInsideHitRegion`). To resolve:
   - Wrap declarations in `extern "C"` blocks.
   - Match implementation signatures exactly (e.g., using `int*` instead of `void` if the wrapper/helper expects a pointer).
   - If stubgen generates colliding dummy stubs for them, whitelist/add the symbol to the ignore list in `tools/stubgen.py`.
2. **Substring Filter Collisions**: The `reccmp-vtable` filter (e.g., `--filter "TView::"`) matches case-insensitively. This can cause unexpected classes to be included in the comparison (e.g., `"TView::"` matches `TCombatReportView` because `t` + `View::` matches `tview::`). Analyze the output carefully to identify which class is the actual mismatch.
3. **Override Signatures**: Ensure derived overrides match the base class virtual signature exactly. Mismatched signatures can cause MSVC to treat them as new virtual functions (shifting the vtable layout) rather than overrides.

## Branch-specific patterns (generalizable)

### TAmtBar branch: TView slot reuse, not extra virtuals

`TAmtBar` inherits `TView` directly (not `TControl`). The binary only has **three**
TAmtBar-introduced tail slots (`0x1a0`–`0x1a8`: `ApplyMoveClamp`, `UpdateBarValuesAndRefresh`,
`RenderPrimarySurfaceOverlayPanelWithClipCache`); slots `0x1ac`+ are NULL in orig. Do **not**
declare the long `vmethod_011x` / `SetBitmap` list as `virtual` — that bloats the recomp vtable
and leaves orig tail slots as `no orig`.

Before those three tail slots, TAmtBar **reuses TView slot signatures** for unrelated bodies:

| Slot | Base virtual | TAmtBar body at |
|---|---|---|
| `0xdc` | `NoOpUiLifecycleHook` | `0x588610` |
| `0x110` | `ApplyRectSlot110` | `0x588670` (`InvokeSlot1A8NoArg`) |
| `0x11c` | `BeginMouseCaptureAndStartRepeatTimer` | `0x588950` (`ClampAndApplyTradeMoveValue`) |

Declare `override` with the **base signature**; put the real body + `// FUNCTION:` marker on the
override. Derived amt bars (e.g. `TTraderAmtBar`) then override individual slots again
(`NoOpUiLifecycleHook` → `DoPostCreate`, `ApplyMoveClamp` → `AdjustForZero`, etc.).

### TPictureResourceEntryBase mid-branch

Slot `0x20` needs `CloneEngineerDialogStateToNewInstance` (`0x48f640`), not `TControl`'s
cannot-clone stub. Slot `0x110` needs `ApplyRectSlot110` (`0x48f3c0`), not `TView`'s empty stub.
Fix once on the base; all picture-resource descendants inherit it.

### TCluster branch

`TCluster` overrides slot `0x20` with `WrapperFor_CopyCityDialogStateFromSource` (`0x4918a0`) —
allocate via `HandleTurnEventVtableSlot24CopyPayloadBuffer()`, then `CopyCityDialogStateFromSource`
+ copy `field84`. Introduced slots `0x1c4`/`0x1c8` are `GetField84` (`0x491770`) and
`SetControlClassAndRefresh` (`0x491790`). Fix on `TCluster`, not per-toolbar.

### Free `__fastcall` wrappers → real overrides

When a class-specific vtable slot points at a free function taking `(Class* this, …)` as its
first argument (e.g. `WrapperFor_HandleCityDialogToggleCommandOrForward_At0058b7f0` on `THQButton`),
promote to a **real `virtual override`** on the class (`HandleEvent`, `NoOpUiLifecycleHook`,
`SetControlStateFlagAndMaybeRefresh`, …) with the base's exact virtual signature. Remove the
free-function `__fastcall` wrapper and any duplicate `// FUNCTION:` marker elsewhere for that
address.

### Ported but non-virtual

If reccmp shows `Class::MethodName` at a slot but the source has a plain method (no `virtual`),
add `override` with the **base slot's virtual name/signature**, move the `// FUNCTION:` marker
onto it, and keep the existing body (`TCivToolbar::HandleCivilianMapCommandPanelAction` →
`HandleEvent`, `TTraderAmtBar::DoPostCreate` → `NoOpUiLifecycleHook`).

### Marker address order vs. source layout

`// FUNCTION:` markers must be **ascending by address within each file** (`just decomplint`
`function_out_of_order`). When vtable overrides live at lower addresses than ctor/factory
functions in the same `.cpp` (common for `0x571xxx` control handlers vs `0x58bxxx` class
methods), put the low-address overrides **first** in the file, then factories/ctors/SYNTHETIC
dtor, then higher-address methods.

### Scalar deleting destructor tooling

Canonical name: ``Class::`scalar deleting destructor'`` via `// SYNTHETIC:` + `config/symbols.csv`.
Run `just correct-scalar-dtors` and `just synthetic-gate` (in `just gates`) after bulk renames.

### ILT thunk un-import

Remove claimed ILT thunk rows from `config/symbols.csv` and repoint callsites to the real method
so reccmp can resolve `jmp` thunks in vtable slots (see [[imported-thunks-block-vtable-resolution]]).
