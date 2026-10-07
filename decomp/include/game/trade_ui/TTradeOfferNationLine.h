#pragma once

#include "compat.h"
#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e2b8
class TTradeOfferNationLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeOfferNationLine)
  // FUNCTION: IMPERIALISM 0x005bcfa0
  virtual ~TTradeOfferNationLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  short categorySlot;
  short nationSlot;

  // NOOP: verified empty in original 0x005bcff3
  TTradeOfferNationLine() {}

  void ITradeOfferNationLine(short categorySlot, short nationSlot, short rowArg, short colArg,
                             int* bounds);
};

ASSERT_SIZE(TTradeOfferNationLine, 0x14);
