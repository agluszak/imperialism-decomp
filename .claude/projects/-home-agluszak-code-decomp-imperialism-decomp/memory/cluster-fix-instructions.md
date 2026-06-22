---
name: cluster-fix-instructions
description: Step-by-step recipe to drive the TCluster family (~21 classes) to vtable 100%, using the proven city-minister reconstruction method
metadata:
  type: project
---

# Fixing the cluster family (TCluster + ~21 derived)

`TCluster : TControl` (vtable **0x64b0c0**). 21 derived clusters (TToolBarCluster,
TTradeCluster, TAmtBarCluster, TCityBarCluster, TProductionCluster, TIndustryCluster,
TRailCluster, TShipyardCluster, TDipDlgCluster, TRadioTextCluster, TMapEditCluster,
TNavyToolbarCluster, TPurchaseCluster, TUberCluster, TTradePolicyCluster, …) inherit
TCluster's broken base, so **fix TCluster first — descendants cascade**. This is the
**same defect class** as the city-minister cluster I just took to 100% (commit 3259fae);
follow that recipe exactly.

## The defect (identical to city-ministers)

`#define override` is empty in `compat.h`, so MSVC matches an override **only by
name+signature**. TCluster's failures are three overlapping bugs:

1. **Junk-named overrides** — TCluster re-declares inherited TView/TControl slots with
   invented names (`Free`, `OwnerPanel`, `DispatchSlot9CToLinkedChildren`,
   `QueryOwnerContextPanel`, `IsActionable`, `vmethod_0076`, `vmethod_0078`, …). Because
   the name ≠ the ancestor's slot name, MSVC **appends** each as a NEW virtual instead of
   overriding → the vtable grows and shifts. Example from the diff:
   `vtable0x1c : -(0x48b0b0) TView::CloseCityDialogChildrenAndReleaseSelf` (orig) vs
   `+(no orig) TCluster::Free` (our junk append).
2. **Duplicate parallel decl sets** — like TCityInteriorMinister had GENERATED DECLS +
   a manual `CityInteriorSlot*` block, TCluster likely has marked real-address methods
   PLUS unmarked junk stubs for the same slots. One set must go.
3. **Adjacent embedded vtable over-read** — the diff shows a "second vtable" (TObject/
   TEventHandler bodies at byte ~0x228+). This is **NOT a base and NOT the blocker** — it
   is a separate heap/member subobject vtable that merely sits next in `.rdata`. reccmp
   over-reads into it **only because our vtable is the wrong length**. Once the primary
   vtable is the correct length with correct names, the over-read disappears. Do **not**
   try to model it as a base. (Same as the minister 0x650a08 collection.)

## Authoritative slot names live in the foundation headers

`TObject → TEventHandler → TView → TControl` are **100%**. The real slot→name map is in
their hand-curated headers, tagged `// 0x<slotidx> [0xADDR]`:
- `include/game/TView.h` (vtable 0x649858)
- `include/game/TControl.h` (vtable 0x64a098)
- `include/game/TEventHandler.h`
Resolve every TCluster override name from the **nearest ancestor header**, never from the
manifest/Ghidra junk name. See [[vtable-oversize-override-name-root-cause]],
[[ui-vtable-hierarchy-ground-truth]], [[cluster-vtable-ground-truth]].

## Recipe (per the proven minister method)

1. **Get ground truth for TCluster's vtable:**
   ```
   just ghidra-vtable-dump TCluster 0x0064b0c0
   ```
   Note byte_offset → entry_addr for every slot. Resolve ILT thunks (0x40xxxx) to the
   real `0x48xxxx`/`0x49xxxx` body with `just ghidra-listing 0xTHUNK` (follow the `JMP`).
   Find where the primary vtable ends (the null run / where a NEW unrelated vtable with
   `CObject::GetRuntimeClass` at slot 0 begins) — that boundary is the real slot count.

2. **Classify each slot** against TControl's vtable (dump `just ghidra-vtable-dump
   TControl 0x0064a098`): for each TCluster slot, is the body the **same** as TControl's
   (inherited → no decl), or **different** (TCluster override → declare with the ancestor
   slot's exact name+signature), or **past TControl's extent** (genuinely new → declare in
   slot order with a stable `ClusterSlotNN` name)?

3. **Edit `include/game/TCluster.h`:**
   - For every override slot, use the **ancestor header's name+signature** (e.g. the slot
     that is really `TView::CloseCityDialogChildrenAndReleaseSelf` must be declared with
     that exact signature, not `Free`).
   - Delete duplicate/parallel junk decls so each slot is declared **once**.
   - Add any **missing tail slots** in order.
   - Genuinely-new cluster virtuals: keep in exact slot order (declaration order == vtable
     order for new virtuals — a misplaced decl shifts everything after it).

4. **Edit `src/game/TCluster.cpp` to match:** rename each marked body to its new decl
   name; **keep the `// FUNCTION: IMPERIALISM 0xADDR` marker** on the real body (reccmp
   pairs by address, so the marker is what matters — body content can stay a stub).
   Delete the unmarked duplicate stubs. Move any body that belongs to a base
   (TControl/TView) out of TCluster (it should already be owned there).

5. **Preserve external callers.** Before deleting/renaming a method that other files call
   (`grep -rn "->MethodName(" src`), either keep that name as the canonical slot name or
   fix the callers. (For ministers I kept `CityInteriorSlot20`/`GetHomeCityRecordIndexSlotC0`/
   `CallD4` for exactly this reason.) Personality/leaf clusters that `override` a slot must
   use the SAME name the base now declares.

6. **Ownership/symbols when moving a body between classes:** update the
   `config/function_ownership.csv` row (address → owning `.cpp`) and the
   `config/symbols.csv` name. One owner per address (Hard Rule 4).

7. **Build & measure, iterate:**
   ```
   just regen-stubs && just build && just detect && just vtable TCluster
   ```
   Read the remaining red slots, fix, repeat. A clean `// FUNCTION` marker placement is
   required: the marker must be **immediately** followed by the declaration (Hard Rule 3) —
   put descriptive comments ABOVE the marker.

8. **Verify the cascade:** once TCluster is 100%, check 2–3 derived
   (`just vtable TTradeCluster`, etc.). Each derived may still have a few of its OWN
   junk-named overrides — fix those the same way (rename leaf override → base slot name).

## Pitfalls (learned the hard way on ministers)

- **Order edits so string anchors stay unique.** Delete the unmarked junk-stub block
  BEFORE renaming a marked body to a name that collides with a stub (otherwise a
  block-delete by `s.index("...Foo() {}")` matches the wrong occurrence and wipes real
  bodies). Build after each class.
- **Don't model the adjacent embedded vtable as a base.** It's a member subobject; it
  stops appearing in the diff once the primary vtable length is right.
- **Override signatures must match the ancestor exactly** (return type + params), or the
  override silently becomes a new appended slot again.
- Run `just marker-gate`, `just antipattern-gate`, `just vtable-gate`, `just stats` before
  committing; commit per the workflow (gates → build → stats → stats-commit).

Expected payoff: TCluster + ~21 derived ≈ a 15-20 class drop in `just vtable not matching`
if the cascade is as clean as the picture/minister families. See [[vtable-campaign-state]].
