#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct BattleOutcomeData {
  unsigned char winnerId; // index into g_apTerrainTypeDescriptorTable
  unsigned char loserId;
  short location;         // city record index for the location name
  short winnerCounts[30]; // per-unit-type counts for the winner
  short loserCounts[30];  // per-unit-type counts for the loser
};

// VTABLE: IMPERIALISM 0x667d08
class TStratReportView : public TView {
  DECLARE_DYNCREATE(TStratReportView)
public:
  BattleOutcomeData* battleOutcome;

  TStratReportView();
  virtual ~TStratReportView() override;

  virtual void Draw(RECT* rectBuffer) override;
};
ASSERT_SIZE(TStratReportView, 0x64);
