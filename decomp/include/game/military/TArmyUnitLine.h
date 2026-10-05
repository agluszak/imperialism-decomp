#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x0064ce80
class TArmyUnitLine : public TLineData {
public:
  DECLARE_DYNCREATE(TArmyUnitLine)
  // FUNCTION: IMPERIALISM 0x004a8d90
  virtual ~TArmyUnitLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4a8df0

  TArmyUnitLine();

  void IArmyUnitLine(short rowArg, short colArg, int* bounds, TMilitaryUnit* item);
  TMilitaryUnit* militaryUnit;
};

ASSERT_SIZE(TArmyUnitLine, 0x14);
