#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x0064d550
class TMiniArmyView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniArmyView)
  virtual ~TMiniArmyView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004ab1d0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4aaeb0
  virtual void Hilite();                        // slot 0x71 0x4aad20
  // The displayed unit: name (CString) and tileIndex read by Draw/DoEvent.
  TMilitaryUnit* militaryUnit; // +0x84

  // NOOP: verified empty in original 0x004aadc6
  TMiniArmyView() {}

  void InitializeForMilitaryUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                 TMilitaryUnit* unit);
};
ASSERT_SIZE(TMiniArmyView, 0x88);
