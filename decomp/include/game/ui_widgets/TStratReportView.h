#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct BattleOutcomeData {
  unsigned char winnerId; // 0x00 — index into g_apTerrainTypeDescriptorTable
  unsigned char loserId;  // 0x01
  short location;         // 0x02 — city record index for the location name
  short winnerCounts[30]; // 0x04..0x3f — per-unit-type counts for the winner
  short loserCounts[30];  // 0x40..0x7b — per-unit-type counts for the loser
};

// VTABLE: IMPERIALISM 0x667d08
class TStratReportView : public TView {
  DECLARE_DYNCREATE(TStratReportView)
public:
  BattleOutcomeData* battleOutcome; // 0x60

  TStratReportView();
  virtual ~TStratReportView() override;

  virtual void Draw(RECT* rectBuffer) override;
};
ASSERT_SIZE(TStratReportView, 0x64);
