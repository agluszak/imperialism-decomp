#pragma once

#include "game/TBehavior.h"
#include "game/mfc.h"

class TEvent;
class TEventHandler;
struct TToolboxEvent;

// VTABLE: IMPERIALISM 0x00648da8
class TDialogBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TDialogBehavior)
  virtual ~TDialogBehavior() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a OrphanTiny_SetDwordEcxOffset_8_00487280 inherited unchanged (0x487280)
  // slot 0x0b OrphanLeaf_NoCall_Ins02_004872a0 inherited unchanged (0x4872a0)
  // slot 0x0c CreateTDialogBehaviorInstance inherited unchanged (0x4872c0)
  // slot 0x0d OrphanRetStub_004872e0 inherited unchanged (0x4872e0)
  virtual void Dismiss(unsigned long commandCode, unsigned char accepted); // slot 0x0e 0x487430
  virtual void DoEvent(long commandId, TEventHandler* sourceHandler,
                       TEvent* event);                  // slot 0x0f 0x487470
  virtual void DoKeyEvent(TToolboxEvent* event);        // slot 0x10 0x4874b0
  virtual void DoCommandKeyEvent(TToolboxEvent* event); // slot 0x11 0x4875d0
  virtual void PoseModally();                           // slot 0x12 0x487660

  void SetUiColorDescriptorGoldTriplet(unsigned char flag, int colorA, int colorB);

  // --- TDialogBehavior data members (object size 0x24; the TBehavior base ends at 0x10).
  // field14/18 hold 4-char command codes (default 0x20202020 == "    " == unbound); the
  // keyboard handlers (slots 0x10/0x11) fire the default command on Enter/Return and the
  // cancel command on Escape/Delete. ---
  unsigned char armed; // 0x10 — state/flag byte
  unsigned char padding_11_13[0x03];
  unsigned long defaultCommandCode; // 0x14 — command fired on Enter/Return
  unsigned long cancelCommandCode;  // 0x18 — command fired on Escape/Delete
  unsigned long armedCommandCode;   // 0x1c — command armed via slot 0x0e
  unsigned char dismissPending;     // 0x20 — set by Dismiss, cleared before the modal loop
  unsigned char padding_21_23[0x03];

  TDialogBehavior();
};

ASSERT_SIZE(TDialogBehavior, 0x24);
