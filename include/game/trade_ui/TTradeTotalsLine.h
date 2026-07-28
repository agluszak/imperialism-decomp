#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e1f8
class TTradeTotalsLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeTotalsLine)
  virtual ~TTradeTotalsLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5c19c0

  TTradeTotalsLine();

  // Two-phase init (MacApp IViewClass idiom): sets the shared TLineData row/bounds
  // then this line's nationSlot. 0x005c1980, __thiscall.
  void ITradeTotalsLine(short rowArg, short colArg, int* bounds, short value);

  short nationSlot;
  short padding12;
};

ASSERT_SIZE(TTradeTotalsLine, 0x14);
