#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/battle_report_records.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e9d0
class TBatRepDetLine : public TLineData {
public:
  DECLARE_DYNCREATE(TBatRepDetLine)
  virtual ~TBatRepDetLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4b0040

  TBatRepDetLine();

  // Original object size is 0x18 (CRuntimeClass m_nObjectSize); the source class ended at 0x10. Trailing 8 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  BattleRecord* battleRecord10;
  BattleReportDetailRecord* battleDetail14;
};
ASSERT_SIZE(TBatRepDetLine, 0x18);
