// The original TCivMgr translation unit was compiled with frame-pointer omission
// (matches the empty sibling stubs' prologue/epilogue better than the default).
#pragma optimize("y", on)
#include "game/TCivMgr.h"

#include "decomp_types.h"
#include "game/TCivUnit.h"
#include "game/TGlobalMapState.h"
#include "game/UiRuntimeContext.h"
#include "game/TUiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TGreatPower.h"
#include "game/TMapUberPicture.h"
#include "game/TViewMgr.h"
#include "game/localization_text_helpers.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

extern "C" {
extern short g_awEngineerFortBuildCostByLevel[8];
extern int g_adwEngineerRailBuildCostByTerrainType[16];
}
undefined4 GetTickCountDiv16(void);
IMPLEMENT_DYNCREATE(TCivMgr, TObject)

TCivMgr::TCivMgr() {}

// SYNTHETIC: IMPERIALISM 0x004d2070
// TCivMgr::`scalar deleting destructor'
TCivMgr::~TCivMgr() {}

// FUNCTION: IMPERIALISM 0x004d2270
void TCivMgr::DispatchSelectedUnitToGlobalMapStateHandler(int* pUnitOrderEntry) {}

// FUNCTION: IMPERIALISM 0x004d2380
bool TCivMgr::HandleCivilianTileSelectionOrReportClick(short nTileIndex, short nClickMode) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d26d0
bool TCivMgr::HandleCivilianTileOrderAction(short nTileIndex, short nInputHint) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d3a60
bool TCivMgr::HandleEngineerConstructionAction(short nTileIndex) {
  TCivUnit* pCiv = this->field04;
  if (pCiv == nullptr) {
    return false;
  }

  bool actionFinalized = false;
  bool refreshPanel = false;

  if (nTileIndex == pCiv->field_6) {
    int choice = g_pUiRuntimeContext->ShowConstructionOptionsDialog();
    if (choice == 0x666f7274) { // 'fort'
      short cityIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
      int fortLevel = g_pGlobalMapState->cityScoreTable[cityIndex].pad03;
      short cost = g_awEngineerFortBuildCostByLevel[fortLevel];

      short nationId = g_pUiRuntimeContext->GetActiveNationId();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue10;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < cost) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pLocalizationTable->FormatIntegerString(cost, &costString);
        g_pLocalizationTable->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pLocalizationTable, &pszFormattedText,
                               static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
            ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &pszFormattedText);
      } else {
        short nationId = g_pUiRuntimeContext->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= cost;
        pCiv->SetOrderModeSlot34(6, pCiv->field_6);
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232c, 0, 1);
        actionFinalized = true;
      }
    } else if (choice == 0x706f7274) { // 'port'
      short nationId = g_pUiRuntimeContext->GetActiveNationId();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue10;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < 3000) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pLocalizationTable->FormatIntegerString(3000, &costString);
        g_pLocalizationTable->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pLocalizationTable, &pszFormattedText,
                               static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
            ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &pszFormattedText);
      } else {
        short nationId = g_pUiRuntimeContext->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= 3000;
        pCiv->SetOrderModeSlot34(7, pCiv->field_6);
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0
              ->InvalidateTileMarkerChain(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232b, 0, 1);
        actionFinalized = true;
      }
    } else if (choice == 0x7261696c) { // 'rail'
      short nationId = g_pUiRuntimeContext->GetActiveNationId();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue10;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < 2000) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pLocalizationTable->FormatIntegerString(2000, &costString);
        g_pLocalizationTable->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pLocalizationTable, &pszFormattedText,
                               static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
            ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &pszFormattedText);
      } else {
        short nationId = g_pUiRuntimeContext->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= 2000;
        pCiv->SetOrderModeSlot34(12, pCiv->field_6);
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0
              ->InvalidateTileMarkerChain(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232a, 0, 1);
        actionFinalized = true;
      }
    }
  } else { // adjacent tile click
    int terrainType = g_pGlobalMapState->terrainStateTable[nTileIndex].pad00[0];
    int cost = g_adwEngineerRailBuildCostByTerrainType[terrainType];

    short nationId = g_pUiRuntimeContext->GetActiveNationId();
    int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
               g_apNationStates[nationId]->treasuryValue10;
    int availableCash = (cash < 0) ? 0 : cash;

    if (availableCash < cost) {
      CString pszFormattedText;
      CString pszTemplateText;
      CString costString;

      g_pLocalizationTable->FormatIntegerString(cost, &costString);
      g_pLocalizationTable->GetString(0x2745, 8, &pszTemplateText);
      scanBracketExpressions(g_pLocalizationTable, &pszFormattedText,
                             static_cast<LPCSTR>(pszTemplateText),
                             static_cast<LPCSTR>(costString));

      reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
          ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &pszFormattedText);
    } else {
      short nationId = g_pUiRuntimeContext->GetActiveNationId();
      g_apNationStates[nationId]->treasuryValue10 -= cost;
      g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(pCiv->field_6, nTileIndex,
                                                                pCiv->field_18);
      pCiv->SetOrderModeSlot34(5, pCiv->field_6);
      g_pSfxPlaybackSystem->PlaySoundEffect(0x2329, 0, 1);
      actionFinalized = true;
      refreshPanel = true;
    }
  }

  if (actionFinalized) {
    this->RelinkCivilianOrderTileAndInvalidateMapTiles(nTileIndex, reinterpret_cast<int*>(pCiv));

    int startTick = reinterpret_cast<int(__cdecl*)(void)>(GetTickCountDiv16)();
    while (true) {
      PumpUiMessagesAndBackgroundTasks(1);
      int now = reinterpret_cast<int(__cdecl*)(void)>(GetTickCountDiv16)();
      if (now < startTick) {
        break;
      }
      if (now - startTick >= 0x1e) {
        break;
      }
    }
  }

  if (refreshPanel) {
    g_pUiRuntimeContext->RefreshViewSlot48();
  }

  return actionFinalized;
}

// FUNCTION: IMPERIALISM 0x004d4310
void TCivMgr::RelinkCivilianOrderTileAndInvalidateMapTiles(short nNewTileIndex,
                                                           int* pCivOrderEntry) {}
