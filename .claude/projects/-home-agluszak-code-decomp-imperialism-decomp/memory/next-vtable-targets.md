---
name: next-vtable-targets
description: 2026-06-15 vtable session handoff — what's 1 slot from 100% and the picture-resource extent unblock
metadata:
  type: project
---

After the 2026-06-15 vtable session (TCluster→100%, commits bc55f58 / 2b3b9f3; see
[[tubercluster-vtable-reconstruction]]), global `just vtable` not-matching ≈ 75. The
cheap GetRuntimeClass/scalar-dtor/non-virtual-rename tier is **exhausted**; everything
left needs real porting or class-recovery. Concrete next targets, easiest first:

**One slot from 100% (both blocked on a slot-0x3c HandleEvent port):**
- **TArmyPlacard** — only slot 0x3c left (`0x58c140`, 115 bytes). It calls slot 0x1cc
  twice (`CALL [vtbl+0x1cc]`). Blocked: slot 0x1cc is an unmodeled virtual. → do the
  picture-resource extent work below first, then port 0x58c140 + the TArmyPlacard slot
  0x1cc override (`0x58bf50`, GetActiveNationId wrapper).
- **TTradeCluster** — only slot 0x3c left (`0x5873e0`, 997 bytes, big HandleEvent). Pure
  port, no prerequisite.

**The picture-resource vtable-extent unblock (high leverage, careful class-recovery):**
TPictureResourceEntryBase (`include/game/TPictureResourceEntryBase.h`) declares NO new
virtuals — but the original introduces **3** after TControl's slots:
- slot 0x1c4 = `0x40421e`→`0x48f520` ResetPictureResourceEntry
- slot 0x1c8 = `0x408454` SetPictureResourceIdAndRefresh
- slot 0x1cc = `0x4012f8`→`0x5708c0` (47-byte orphan)
Declaring these 3 as named virtuals (in order, owning those addrs) lets TPictureButton
override slot 0x1cc (`0x403a85`) and TArmyPlacard override it (`0x58bf50`) — unblocking
TArmyPlacard's HandleEvent. Affects all picture-resource descendants (verify each).

**Entangled picture-button intermediate base (needs more than vtable-layout evidence):**
T2PictureButton / TAlwaysPictureButton / TClosePicture each have only 2 mismatches:
slot 0x11c (`0x570900`, shared by all 3) and slot 0x1c0 (`0x570870` for T2Pic+TClosePic,
`0x570a70` for TAlways). A shared override addr ⇒ a common base defines it, but the
leaves all ctor `: TPictureButton()` directly and Mac shows no named intermediate, so
the structure (new intermediate base vs T2Pic-as-base) is ambiguous (rule 12). Also each
leaf is missing a slot-0x00 GetRuntimeClass override. Needs evidence-driven recovery.

**Other 2-3-slot classes (each needs body ports):** TStaticText (slot 0x20 clone @0x48fc00
clean 24b; slot 0x110 @0x48ffb0 184b render w/ slot-0x160 vcall), TEngineerDialog (slot
0x00 GetRuntimeClass + slot 0x1c + slot 0x110 ports), CBrush (MFC multi-TU scalar-dtor
tangle + slot-0x00 GetRuntimeClass @0x623aa0 / desc 0x672370).
