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
  virtual ~TDialogBehavior() override {}
  virtual void Dismiss(unsigned long commandCode, bool accepted);
  virtual void DoEvent(long commandId, TEventHandler* sourceHandler, TEvent* event);
  virtual void DoKeyEvent(TToolboxEvent* event);
  virtual void DoCommandKeyEvent(TToolboxEvent* event);
  virtual void PoseModally();

  void IDialogBehavior(bool flag, int colorA, int colorB);

  bool armed;                       // state/flag byte
  unsigned long defaultCommandCode; // command fired on Enter/Return
  unsigned long cancelCommandCode;  // command fired on Escape/Delete
  unsigned long armedCommandCode;   // command armed via slot 0x0e
  bool dismissPending;              // set by Dismiss, cleared before the modal loop

  TDialogBehavior();
};

ASSERT_SIZE(TDialogBehavior, 0x24);
