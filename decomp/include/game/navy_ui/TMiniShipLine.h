#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065db28
class TMiniShipLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniShipLine)
  // FUNCTION: IMPERIALISM 0x00569b90
  virtual ~TMiniShipLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  // NOOP: verified empty in original 0x00569be3
  TMiniShipLine() {}

  void IMiniShipLine(short rowArg, short colArg, int* bounds, TShip* item);

  TShip* ship;
};
ASSERT_SIZE(TMiniShipLine, 0x14);
