#pragma once

#include "game/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c350
class TCivAnimation : public TAnimation {
public:
  // === BEGIN GENERATED DECLS (TCivAnimation) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCivAnimation)
  virtual ~TCivAnimation() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined AdvanceAnimationTickAndInvalidateOnFrameFlip() override; // slot 0x0a 0x49f580
  // slot 0x0b RenderBattleReportInsetWithPaletteShift inherited unchanged (0x49f190)
  // slot 0x0c RenderBattleReportViewSurfaceSpriteWithResourceHandle inherited unchanged (0x49f2d0)
  // === END GENERATED DECLS (TCivAnimation) ===

  TCivAnimation();
};
