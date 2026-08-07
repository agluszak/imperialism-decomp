#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e278
class TCommodityLine : public TLineData {
public:
  DECLARE_DYNCREATE(TCommodityLine)
  // FUNCTION: IMPERIALISM 0x005c1520
  virtual ~TCommodityLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5c1580

  TCommodityLine();

  // Two-phase init (MacApp IViewClass idiom): sets the shared TLineData row/bounds
  // then this line's commoditySlot. 0x005c1540, __thiscall.
  void ICommodityLine(short rowArg, short colArg, int* bounds, short value);

  short commoditySlot;
  short padding12;
};

ASSERT_SIZE(TCommodityLine, 0x14);
