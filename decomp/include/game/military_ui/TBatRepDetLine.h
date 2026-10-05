#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/battle_report_records.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e9d0
class TBatRepDetLine : public TLineData {
public:
  DECLARE_DYNCREATE(TBatRepDetLine)
  // FUNCTION: IMPERIALISM 0x004b0000
  virtual ~TBatRepDetLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4b0040

  // NOOP: verified empty in original 0x004aff93 (no standalone TBatRepDetLine::TBatRepDetLine body exists: CreateObject 0x004aff60 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TBatRepDetLine() {}

  BattleRecord* battleRecord10;
  BattleReportDetailRecord* battleDetail;
};
ASSERT_SIZE(TBatRepDetLine, 0x18);
