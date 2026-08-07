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

  // Two-phase init (MacApp IViewClass idiom): sets the shared TLineData row/bounds
  // then this line's militaryUnit10. 0x004a8db0, __thiscall.
  void IArmyUnitLine(short rowArg, short colArg, int* bounds, TMilitaryUnit* item);
  // StuffValues installs the represented stationed-unit node here before adding
  // the line to the page's ordered-entry list.
  TMilitaryUnit* militaryUnit10;
};

ASSERT_SIZE(TArmyUnitLine, 0x14);
