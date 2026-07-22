#pragma once

#include "game/TControl.h"
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
  // The displayed unit: name24 (CString) and tileIndex06 read by Draw/DoEvent.
  TMilitaryUnit* militaryUnit84; // +0x84

  TMiniArmyView();
};
