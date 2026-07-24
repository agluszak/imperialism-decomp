#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x0064d510
class TMiniArmyLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniArmyLine)
  virtual ~TMiniArmyLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4aa960

  // NOOP: verified empty in original 0x004aa8c3 (no standalone TMiniArmyLine::TMiniArmyLine body exists: CreateObject 0x004aa890 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TMiniArmyLine() {}

  // Army unit represented by this roster row.
  TMilitaryUnit* militaryUnit10;
};
ASSERT_SIZE(TMiniArmyLine, 0x14);
