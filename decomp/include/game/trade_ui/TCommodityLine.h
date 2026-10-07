#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e278
class TCommodityLine : public TLineData {
public:
  DECLARE_DYNCREATE(TCommodityLine)
  // FUNCTION: IMPERIALISM 0x005c1520
  virtual ~TCommodityLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  TCommodityLine();

  void ICommodityLine(short rowArg, short colArg, int* bounds, short value);

  short commoditySlot;
  short padding12;
};

ASSERT_SIZE(TCommodityLine, 0x14);
