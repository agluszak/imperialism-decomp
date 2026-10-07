#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e238
class TDealLine : public TLineData {
public:
  DECLARE_DYNCREATE(TDealLine)
  // FUNCTION: IMPERIALISM 0x005c0de0
  virtual ~TDealLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  TDealLine();
  void IDealLine(short rowArg, short colArg, int* bounds, short commoditySlot,
                 short ownerNationSlot, short entryOrdinal);

  short commoditySlot;
  short ownerNationSlot;
  short entryOrdinal;
};

ASSERT_SIZE(TDealLine, 0x18);
