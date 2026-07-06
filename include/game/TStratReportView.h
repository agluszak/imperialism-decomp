#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// Battle-outcome record the report view renders (pointed to by TStratReportView+0x60):
// the two sides' descriptor-table ids, the location, and the per-unit-type counts.
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

  // slot 0x110 0x58e460 -- renders the battle-outcome header winner/loser
  // score lines; body not yet fully ported (CString/QuickDraw table render).
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
};
