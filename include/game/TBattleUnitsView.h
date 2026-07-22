#pragma once

#include "game/TMilitaryPageView.h"
#include "game/battle_report_records.h"

#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640940
class TBattleUnitsView : public TMilitaryPageView {
public:
  DECLARE_DYNCREATE(TBattleUnitsView)
  virtual ~TBattleUnitsView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;        // slot 0x28 0x4b0900

  TBattleUnitsView();
  void StuffValues(BattleRecord* battleRecord, int participantIndex);

  TQuickDrawSurfaceContext* secondaryUnitAtlas88;
};
