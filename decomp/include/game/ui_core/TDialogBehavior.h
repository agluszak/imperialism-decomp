#pragma once

#include "game/ui_core/TBehavior.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TEvent;
class TEventHandler;
struct TToolboxEvent;

// VTABLE: IMPERIALISM 0x00648da8
class TDialogBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TDialogBehavior)
  // FUNCTION: IMPERIALISM 0x004873e0
  virtual ~TDialogBehavior() override {} // slot 0x01 (scalar deleting destructor)
  virtual void Dismiss(unsigned long commandCode, bool accepted); // slot 0x0e 0x487430
  virtual void DoEvent(long commandId, TEventHandler* sourceHandler,
                       TEvent* event);                  // slot 0x0f 0x487470
  virtual void DoKeyEvent(TToolboxEvent* event);        // slot 0x10 0x4874b0
  virtual void DoCommandKeyEvent(TToolboxEvent* event); // slot 0x11 0x4875d0
  virtual void PoseModally();                           // slot 0x12 0x487660

  void IDialogBehavior(bool flag, int colorA, int colorB);

  bool armed; // 0x10 — state/flag byte
  unsigned char padding_11_13[0x03];
  unsigned long defaultCommandCode; // 0x14 — command fired on Enter/Return
  unsigned long cancelCommandCode;  // 0x18 — command fired on Escape/Delete
  unsigned long armedCommandCode;   // 0x1c — command armed via slot 0x0e
  bool dismissPending;              // 0x20 — set by Dismiss, cleared before the modal loop
  unsigned char padding_21_23[0x03];

  TDialogBehavior();
};

ASSERT_SIZE(TDialogBehavior, 0x24);
