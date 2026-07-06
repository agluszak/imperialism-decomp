#pragma once

#include "game/TControl.h"

// Provisional interface for the 'crus' cursor-info control (g_pCursorControlPanel,
// resolved via ResolveControlByTag(kControlTagCrus)). Concrete-class recovery in
// progress (bd imperialism-decomp-hpd.8):
//   * The UI factory registers 'crus' as a TInfoBarText (see
//     turn_event_dialog_factory.cpp:671/1139 + the comment at :701 "a 'crus'
//     TInfoBarText"). TInfoBarText is a real recovered class: VTABLE 0x0063eb00,
//     ASSERT_SIZE 0xb4 (RTTI oracle), base TDeluxeText.
//   * UpdateCursorState() below sits at slot 0x80 / byte 0x200, which on TInfoBarText
//     is SetTextAndLayoutRect(CString, RECT*) (0x5b66b0, RET 0x8 = two args).
//   * BLOCKER: the only dispatch of byte 0x200 on this control
//     (TView::HandleCursorHoverFallback 0x0048c250) pushes NO arguments — verified
//     matching in both original and recomp — so the crus control's byte-0x200 method
//     is effectively a no-arg call. That is inconsistent with TInfoBarText's 2-arg
//     SetTextAndLayoutRect, so the crus control is probably a TInfoBarText *subclass*
//     that overrides byte 0x200 with a no-arg refresh, or the factory registers a
//     TInfoBarText subtype not yet in the RTTI oracle. Next step: trace the concrete
//     ctor/vtable the 'crus' RegisterUiResourceEntry path installs to confirm the
//     subtype before folding this placeholder into the real class.
class TCursorControlPanel : public TControl {
public:
  // Slots 113-127 (0x1C4-0x1FC)
  virtual void dummy_113() = 0;
  virtual void dummy_114() = 0;
  virtual void dummy_115() = 0;
  virtual void dummy_116() = 0;
  virtual void dummy_117() = 0;
  virtual void dummy_118() = 0;
  virtual void dummy_119() = 0;
  virtual void dummy_120() = 0;
  virtual void dummy_121() = 0;
  virtual void dummy_122() = 0;
  virtual void dummy_123() = 0;
  virtual void dummy_124() = 0;
  virtual void dummy_125() = 0;
  virtual void dummy_126() = 0;
  virtual void dummy_127() = 0;

  // Slot 128 (0x200)
  virtual void UpdateCursorState() = 0;
};
