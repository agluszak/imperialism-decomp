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
  virtual ~TBatRepDetLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  // NOOP: verified empty in original 0x004aff93
  TBatRepDetLine() {}

  BattleRecord* battleRecord;
  BattleReportDetailRecord* battleDetail;
};
ASSERT_SIZE(TBatRepDetLine, 0x18);
