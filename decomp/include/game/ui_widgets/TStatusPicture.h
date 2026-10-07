#pragma once

#include "game/ui_core/TPicture.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/military_ui_globals.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642268
class TStatusPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TStatusPicture)
  virtual ~TStatusPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  int comparisonMode;  // selects which per-nation metric fills values
  int values[7];       // per-entry sort key (score)
  short pictureIds[7]; // per-entry picture id (-1 = empty slot)

  TStatusPicture();

  void DrawBar(short rowY, short width, short nationSlot);
  void SwitchStatusMode(int comparisonMode);
  void SortByBarLength();
  void CalcCouncilGraph();
  void CalcStandardGraph() {
    g_pDiplomacyTurnStateManager->CalculateRatings();
    for (int i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(i))) {
        int sum = 0;
        int* metric = g_pDiplomacyTurnStateManager->comparativePowerRows[i];
        int metricCount = 4;
        do {
          sum += *metric;
          ++metric;
          --metricCount;
        } while (metricCount != 0);
        values[i] = static_cast<short>(sum) * 400 / 400;
        pictureIds[i] = static_cast<short>(i);
      } else {
        pictureIds[i] = -1;
      }
    }
    SortByBarLength();
  }
  // Retained VC5 copy of a method inlined at its only live callsite.
  void NormalizeAsNeeded() {
    int maxValue = values[0];
    if (maxValue > 400) {
      values[0] = 400;
      for (int index = 1; index < 7; ++index) {
        if (pictureIds[index] != -1) {
          values[index] = values[index] * 400 / maxValue;
        }
      }
    }
  }
};

ASSERT_SIZE(TStatusPicture, 0xc0);
