#pragma once

#include "compat.h"
#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e4f0
class TTradeBidNationLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeBidNationLine)
  // FUNCTION: IMPERIALISM 0x005bd930
  virtual ~TTradeBidNationLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  short categorySlot;
  short nationSlot;

  // NOOP: verified empty in original 0x005bd983
  TTradeBidNationLine() {}

  void ITradeBidNationLine(short categorySlot, short nationSlot, short rowArg, short colArg,
                           int* bounds);
};

ASSERT_SIZE(TTradeBidNationLine, 0x14);
