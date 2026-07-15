#pragma once

#include "compat.h"
#include "game/TAnimation.h"
#include "game/mfc.h"

// CONFIRMED REAL CLASS: RTTI CRuntimeClass descriptor `classTCivAnimation2` at
// 0x64c220 (DYNCREATE, symbols.csv row 7965) gives the true name and base edge
// TCivAnimation2 -> TAnimation -> TObject -> CObject; vtable @ 0x64c390 has 13
// distinct slots (not folded with TAnimation/TOneTimeAnimation), and it is
// upcast-constructed as a real object in TCouncilTickerAnimation.cpp
// (g_pUiAnimator) and TMapDialog.cpp. It is a battle-report civ animation
// state machine, not a misattribution.
// (AddObjectToUiTransientRegistry 0x4a0d10 and the registry walker 0x4a0d30,
// once bucketed here by Ghidra, are really TAnimator methods -- the receiver
// is the g_pUiAnimator global, proven by the callers' `mov ecx,[0x6a43e0]`.)
// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
  // === BEGIN GENERATED DECLS (TCivAnimation2) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCivAnimation2)
  virtual ~TCivAnimation2() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined AdvanceAnimationTickAndInvalidateOnFrameFlip() override; // slot 0x0a 0x49f7c0
  virtual undefined RenderBattleReportInsetWithPaletteShift() override;      // slot 0x0b 0x49f8e0
  // slot 0x0c RenderBattleReportViewSurfaceSpriteWithResourceHandle inherited unchanged (0x49f2d0)
  // === END GENERATED DECLS (TCivAnimation2) ===
  // TAnimation's own slice ends at 0x2c (ASSERT_SIZE); RTTI oracle confirms
  // sizeof(TCivAnimation2) == 0x30. Caches the ctor's `kind` selector (see the ctor
  // below) for later reference; real reader not yet identified.
  short kindIndex2c; // +0x2c
  short pad2e;       // +0x2e

  TCivAnimation2();

  // Real ctor (0x49f6a0): looks up a per-kind (stringId, ticksPerFrame) pair from two
  // 9-entry tables baked into the original as immediate stores (kind 0..8 -- battle
  // report civ animation variants) and forwards them to the already-ported
  // TAnimation::ConstructTAnimationBaseState with frameCount pinned to 0 (this class
  // overrides AdvanceAnimationTickAndInvalidateOnFrameFlip itself, so the inherited
  // frame-index scheme is unused). Confirmed against both call sites
  // (OrphanTiny_ReturnZero_0048a730 and ApplyRectSlot110): param_1 is the enclosing
  // TView, param_2 a RECT computed from a (x,y) origin, param_3 the kind index read
  // from another object's +0x4 field, param_4 an opaque tag forwarded verbatim.
  TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag);
};

ASSERT_SIZE(TCivAnimation2, 0x30);
