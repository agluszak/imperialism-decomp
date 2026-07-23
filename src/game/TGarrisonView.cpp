#include "game/TGarrisonView.h"
#include "game/CString.h"
#include "game/TArmyUnitLine.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/TCountry.h"
#include "game/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
// SYNTHETIC: IMPERIALISM 0x004a8770
// TGarrisonView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a87f0
// TGarrisonView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGarrisonView, TMilitaryPageView)

// FUNCTION: IMPERIALISM 0x004a8810
TGarrisonView::TGarrisonView() {}

// FUNCTION: IMPERIALISM 0x004a8890
void TGarrisonView::StuffValues(short tileIndex) {
  PrepareUnitCache(0xdb8, 0xeff, 0x30);

  CString unusedTextA;
  CString unusedTextB;
  selectedTileIndex8C = tileIndex;

  TMilitaryUnit* unit = 0;
  if (tileIndex >= 0 && tileIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
  }

  int lineBounds[2] = {0xec, 0x31};
  while (unit != 0) {
    if (unit->unitOrder != kUnitOrderRedeploy) {
      TArmyUnitLine* line = new TArmyUnitLine;
      line->SetLineDataRowAndBounds(0, 0, lineBounds);
      line->militaryUnit10 = unit;
      AddOrderedEntry(line);
    }
    unit = static_cast<TMilitaryUnit*>(unit->nextOnTile);
  }

  AfterStuffValues();
}

// SYNTHETIC: IMPERIALISM 0x004a8840
// TGarrisonView::`scalar deleting destructor'
TGarrisonView::~TGarrisonView() {}

// FUNCTION: IMPERIALISM 0x004a8a20
void TGarrisonView::Close() {
  enum { kDismissOnCloseOrderState = 0x0e };

  short tileIndex = selectedTileIndex8C;
  if (tileIndex != -1) {
    unsigned char hasDismissibleOrder = 0;
    TMilitaryUnit* unit = 0;
    if (tileIndex >= 0 && tileIndex < 0x180) {
      unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
    }
    while (unit != 0 && hasDismissibleOrder == 0) {
      if (unit->unitOrder == static_cast<UnitOrder>(kDismissOnCloseOrderState)) {
        hasDismissibleOrder = 1;
      }
      unit = static_cast<TMilitaryUnit*>(unit->nextOnTile);
    }

    if (hasDismissibleOrder != 0) {
      if (g_pSimMgr->preferenceValues[8] != 0) {
        hasDismissibleOrder =
            g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x2746, 9, 1, 1);
      }
      if (hasDismissibleOrder != 0) {
        tileIndex = selectedTileIndex8C;
        unit = 0;
        if (tileIndex >= 0 && tileIndex < 0x180) {
          unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
        }
        while (unit != 0) {
          if (unit->unitOrder == static_cast<UnitOrder>(kDismissOnCloseOrderState)) {
            TMilitaryUnit* nextUnit = static_cast<TMilitaryUnit*>(unit->nextOnTile);
            CString unitName;
            unitName = unit->name24;
            unsigned char isSecretUnit =
                _mbscmp(
                    reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(unitName)),
                    reinterpret_cast<const unsigned char*>(g_szGarrisonSecretUnitNameSnidely)) == 0;
            if (isSecretUnit != 0) {
              CString activeNationName;
              short activeNation = g_pSimMgr->GetActiveNationId();
              g_apTerrainTypeDescriptorTable[activeNation]->FormatOverlayTerrainLabelText(
                  &activeNationName);
              unsigned char isSecretNation =
                  _mbscmp(
                      reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(activeNationName)),
                      reinterpret_cast<const unsigned char*>(g_szGarrisonSecretNationNameFrog)) ==
                  0;
              if (isSecretNation != 0) {
                activeNation = g_pSimMgr->GetActiveNationId();
                if (g_apTerrainTypeDescriptorTable[activeNation]->GetHomeRegionCityRecordIndex() ==
                    selectedTileIndex8C) {
                  g_nationInfoGoldResourceOverride_006a5bac = 0x24d0;
                }
              }
            }
            unit->DetachUnitOrderFromOwnerAndReset();
            unit->Free();
            unit = nextUnit;
          } else {
            unit = static_cast<TMilitaryUnit*>(unit->nextOnTile);
          }
        }
      }
    }
  }
  TMilitaryPageView::Close();
}
