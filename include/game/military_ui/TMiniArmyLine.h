#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x0064d510
class TMiniArmyLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniArmyLine)
  virtual ~TMiniArmyLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4aa960

  TMiniArmyLine();

  // Army unit represented by this roster row.
  TMilitaryUnit* militaryUnit10;
};
