#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d100
class TArmyUnitView : public TView {
public:
  DECLARE_DYNCREATE(TArmyUnitView)
  virtual ~TArmyUnitView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004a9990
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4a95b0
  // Offsets read by Draw (+8 int, +0x24 CString, +0x34/+0x38 short)
  // match TMilitaryUnit::unitOrder/name24/field_34/field_38 exactly.
  class TMilitaryUnit* militaryUnit60; // +0x60

  // Non-virtual: runs the rename dialog for militaryUnit60 in response to the 'name' command.
  void HandleCrossUArmyViewsNameCommand();

  TArmyUnitView();
};
