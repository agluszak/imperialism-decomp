#include "game/military/TGarrisonView.h"

#include <mbstring.h>

#include "game/core/CString.h"
#include "game/military/TArmyUnitLine.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

IMPLEMENT_DYNCREATE(TGarrisonView, TMilitaryPageView)

// FUNCTION: IMPERIALISM 0x004a8810
TGarrisonView::TGarrisonView() : TMilitaryPageView() {
  selectedTileIndex = -1;
}

// FUNCTION: IMPERIALISM 0x004a8870
TGarrisonView::~TGarrisonView() {}

// FUNCTION: IMPERIALISM 0x004a8890
void TGarrisonView::StuffValues(short tileIndex) {
  PrepareUnitCache(0xdb8, 0xeff, 0x30);

  CString unusedTextA;
  CString unusedTextB;
  selectedTileIndex = tileIndex;

  TMilitaryUnit* unit = 0;
  if (tileIndex >= 0 && tileIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain;
  }

  int lineBounds[2] = {0xec, 0x31};
  while (unit != 0) {
    if (unit->unitOrder != kUnitOrderRedeploy) {
      TArmyUnitLine* line = new TArmyUnitLine;
      line->ILineData(0, 0, lineBounds);
      line->militaryUnit = unit;
      AddOrderedEntry(line);
    }
    unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
  }

  AfterStuffValues();
}

// FUNCTION: IMPERIALISM 0x004a8a20
void TGarrisonView::Close() {
  enum { kDismissOnCloseOrderState = 0x0e };

  short tileIndex = selectedTileIndex;
  if (tileIndex != -1) {
    unsigned char hasDismissibleOrder = 0;
    TMilitaryUnit* unit = 0;
    if (tileIndex >= 0 && tileIndex < 0x180) {
      unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain;
    }
    while (unit != 0 && hasDismissibleOrder == 0) {
      if (unit->unitOrder == static_cast<UnitOrder>(kDismissOnCloseOrderState)) {
        hasDismissibleOrder = 1;
      }
      unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
    }

    if (hasDismissibleOrder != 0) {
      if (g_pSimMgr->preferenceValues[8] != 0) {
        hasDismissibleOrder = g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x2746, 9, 1, 1);
      }
      if (hasDismissibleOrder != 0) {
        tileIndex = selectedTileIndex;
        unit = 0;
        if (tileIndex >= 0 && tileIndex < 0x180) {
          unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain;
        }
        while (unit != 0) {
          if (unit->unitOrder == static_cast<UnitOrder>(kDismissOnCloseOrderState)) {
            TMilitaryUnit* nextUnit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
            CString unitName;
            unitName = unit->name;
            bool isSecretUnit = unitName.Compare(g_szGarrisonSecretUnitNameSnidely) == 0;
            if (isSecretUnit) {
              CString activeNationName;
              short activeNation = g_pSimMgr->GetPlayerCountry();
              g_apTerrainTypeDescriptorTable[activeNation]->FormatOverlayTerrainLabelText(
                  &activeNationName);
              bool isSecretNation = activeNationName.Compare(g_szGarrisonSecretNationNameFrog) == 0;
              if (isSecretNation) {
                activeNation = g_pSimMgr->GetPlayerCountry();
                if (g_apTerrainTypeDescriptorTable[activeNation]->GetCapitolProvince() ==
                    selectedTileIndex) {
                  g_nationInfoGoldResourceOverride = 0x24d0;
                }
              }
            }
            unit->Vaporize();
            unit->Free();
            unit = nextUnit;
          } else {
            unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
          }
        }
      }
    }
  }
  TMilitaryPageView::Close();
}
