#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e1f8
class TTradeTotalsLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeTotalsLine)
  // FUNCTION: IMPERIALISM 0x005c1960
  virtual ~TTradeTotalsLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  TTradeTotalsLine();

  void ITradeTotalsLine(short rowArg, short colArg, int* bounds, short value);

  short nationSlot;
  short padding12;
};

ASSERT_SIZE(TTradeTotalsLine, 0x14);
