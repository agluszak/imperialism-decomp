#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x0064d550
class TMiniArmyView : public TControl {
public:
  DECLARE_DYNCREATE(TMiniArmyView)
  virtual ~TMiniArmyView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Hilite();
  // The displayed unit: name (CString) and tileIndex read by Draw/DoEvent.
  TMilitaryUnit* militaryUnit;

  // NOOP: verified empty in original 0x004aadc6
  TMiniArmyView() {}

  void InitializeForMilitaryUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                 TMilitaryUnit* unit);
};
ASSERT_SIZE(TMiniArmyView, 0x88);
