#pragma once

#include "game/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e1f8
class TTradeTotalsLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeTotalsLine)
  virtual ~TTradeTotalsLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5c19c0

  TTradeTotalsLine();

  short nationId10;
  short padding12;
};

ASSERT_SIZE(TTradeTotalsLine, 0x14);
