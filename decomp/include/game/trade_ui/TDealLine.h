#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e238
class TDealLine : public TLineData {
public:
  DECLARE_DYNCREATE(TDealLine)
  // FUNCTION: IMPERIALISM 0x005c0de0
  virtual ~TDealLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5c0e50

  TDealLine();
  void IDealLine(short rowArg, short colArg, int* bounds, short commoditySlot,
                 short ownerNationSlot, short entryOrdinal);

  short commoditySlot;
  short ownerNationSlot;
  short entryOrdinal;
  short padding16;
};

ASSERT_SIZE(TDealLine, 0x18);
