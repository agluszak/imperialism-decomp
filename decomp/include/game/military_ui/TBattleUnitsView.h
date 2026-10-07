#pragma once

#include "compat.h"

#include "game/navy/TMilitaryPageView.h"
#include "game/battle_report_records.h"

#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640940
class TBattleUnitsView : public TMilitaryPageView {
public:
  DECLARE_DYNCREATE(TBattleUnitsView)
  virtual ~TBattleUnitsView() override;
  virtual void Close() override;

  TBattleUnitsView();
  void StuffValues(BattleRecord& battleRecord, int participantIndex);

  TQuickDrawSurfaceContext* secondaryUnitAtlas;
};
ASSERT_SIZE(TBattleUnitsView, 0x8c);
