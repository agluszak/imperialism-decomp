#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e238
class TDealLine : public TLineData {
public:
  DECLARE_DYNCREATE(TDealLine)
  virtual ~TDealLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5c0e50

  TDealLine();
  // MacApp two-phase init, same family as TCommodityLine::ICommodityLine: forwards the
  // first three arguments to TLineData::SetLineDataRowAndBounds, then stores the three
  // trailing shorts. 0x5c0e00 (RET 0x18 = six stack dwords).
  void IDealLine(short rowArg, short colArg, int* bounds, short commoditySlot,
                 short ownerNationSlot, short entryOrdinal);

  short commoditySlot10;
  short ownerNationSlot12;
  short entryOrdinal14;
  short padding16;
};

ASSERT_SIZE(TDealLine, 0x18);
