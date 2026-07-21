#include "game/TCivMgr.h"

#include "game/TAmbitApplication.h"
#include "decomp_types.h"
#include "game/TAnimator.h"
#include "game/TCivUnit.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/UiRuntimeContext.h"
#include "game/TUiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TGreatPower.h"
#include "game/TCivToolbar.h"
#include "game/TNewsMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TViewMgr.h"
#include "game/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

// 0x005d4890. 'D' (0x44) is the only currently-known remapped shortcut code (keyCode 2);
// other codes pass through as literal virtual-key codes.
static bool IsMappedShortcutKeyPressed(short keyCode) {
  short virtualKey = (keyCode == 2) ? 0x44 : keyCode;
  return (GetKeyState(virtualKey) & 0x8000) != 0;
}

// SYNTHETIC: IMPERIALISM 0x004d2000
// TCivMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d2030
// TCivMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivMgr, TObject)

// FUNCTION: IMPERIALISM 0x004d2050
TCivMgr::TCivMgr() {}

// SYNTHETIC: IMPERIALISM 0x004d2070
// TCivMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004d20a0
TCivMgr::~TCivMgr() {}

// FUNCTION: IMPERIALISM 0x004d20c0
void TCivMgr::ICivMgr() {}

// FUNCTION: IMPERIALISM 0x004d2270
void TCivMgr::DispatchSelectedUnitToGlobalMapStateHandler(TCivUnit* pUnitOrderEntry) {}

// FUNCTION: IMPERIALISM 0x004d2380
bool TCivMgr::HandleCivilianTileSelectionOrReportClick(short nTileIndex, short nClickMode) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d2540
unsigned short TCivMgr::ResolveCivilianTileSelectionOrReportActionCode(short nTileIndex,
                                                                       short nClickMode) {
  int actionKind = 0;
  TCivUnit* entry =
      g_pGlobalMapState->GetTileUnitEntryByOwner(nTileIndex, g_pSimMgr->GetActiveNationId());
  if (entry != nullptr) {
    entry = g_pGlobalMapState->GetTileUnitEntryByOwner(nTileIndex, g_pSimMgr->GetActiveNationId());
    if (entry->IsInIdleSelectionState() == 0) {
      actionKind = 10;
    } else if (nClickMode == 2 ||
               (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags1c >> 5 & 1) == 0) {
      actionKind = 2;
    }
  }
  if (actionKind == 2) {
    return 0x3f9;
  }
  return (actionKind != 10) - 1 & 0x3f3;
}

// FUNCTION: IMPERIALISM 0x004d26d0
bool TCivMgr::HandleCivilianTileOrderAction(short nTileIndex, short nInputHint) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d2930
unsigned short TCivMgr::LookupCivilianTileOrderCursorTokenByActionIndex(short nTileIndex,
                                                                        short nInputHint) {
  int actionCode = this->ResolveCivilianTileOrderActionCode(nTileIndex, nInputHint);
  return g_civilianTileOrderCursorTokenTable[actionCode];
}

// FUNCTION: IMPERIALISM 0x004d2960
int TCivMgr::ResolveCivilianTileOrderActionCode(short nTileIndex, short nInputHint) {
  short nationId = g_pSimMgr->GetActiveNationId();
  TCivUnit* pClickedTileUnit = g_pGlobalMapState->GetTileUnitEntryByOwner(nTileIndex, nationId);

  if ((g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) &&
      ((nTileIndex % 0x6c == 0) || (nTileIndex % 0x6c == 0x6b))) {
    return 1;
  }

  TCivUnit* selectedEntry = this->selectedEntry;
  if (selectedEntry == nullptr) {
    nationId = g_pSimMgr->GetActiveNationId();
    TCivUnit* pOwnedCivilianEntry =
        g_pGlobalMapState->GetTileUnitEntryByOwner(nTileIndex, nationId);
    if (pOwnedCivilianEntry == nullptr) {
      return 0;
    }
    if (!pOwnedCivilianEntry->IsInIdleSelectionState()) {
      return 10;
    }
    if ((nInputHint != 2) &&
        (((g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags1c >> 5) & 1) != 0)) {
      return 0;
    }
    return 2;
  }

  if ((pClickedTileUnit != nullptr) && (pClickedTileUnit != selectedEntry)) {
    return (pClickedTileUnit->field_8 != 0) ? 10 : 2;
  }

  if (IsMappedShortcutKeyPressed(2)) {
    return this->CanAssignCivilianOrderToTile(nTileIndex) ? 3 : 1;
  }

  TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[nTileIndex];
  if (tile->recruitSearchVisited0e == 0) {
    short orderType = selectedEntry->orderType;
    if (orderType == 1) {
      return 8;
    }
    if (orderType == 4) {
      short homeTile = selectedEntry->tileIndex06;
      if (nTileIndex == homeTile) {
        return 4;
      }
      short dir = GetHexDirectionBetweenTiles(homeTile, nTileIndex);
      if ((dir == 1) || (dir == 4)) {
        return 5;
      }
      if ((dir == 0) || (dir == 3)) {
        return 6;
      }
      return 7;
    }
    if (orderType == 7) {
      return 0xb;
    }
    return 9;
  }

  TCivUnit* orderAtTile = tile->firstCivilianOrder20;
  if (orderAtTile != nullptr) {
    nationId = g_pSimMgr->GetActiveNationId();
    if (orderAtTile->field_18 == nationId) {
      return orderAtTile->IsInIdleSelectionState() ? 2 : 10;
    }
  }
  return this->CanAssignCivilianOrderToTile(nTileIndex) ? 3 : 1;
}

// Selection helpers merged from the retired duplicate class
// "TSelectedCivilianOrderState" (the global g_pSelectedCivilianOrderState @0x6a43dc is
// this TCivMgr instance).

// FUNCTION: IMPERIALISM 0x004d2c60
void TCivMgr::SetActiveCivilianSelection(TCivUnit* entryContext, char refreshCommandPanel) {
  this->selectedEntry = entryContext;
  this->DispatchSelectedUnitToGlobalMapStateHandler(entryContext);
  if (entryContext == nullptr) {
    return;
  }

  entryContext->VTableSlot10(entryContext->tileIndex06);

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->InvalidateTileMarkerChain(entryContext->tileIndex06);
  }

  if (refreshCommandPanel != 0) {
    mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
    if (mapUberPicture != nullptr) {
      // categoryPages[] is a heterogeneous array of toolbar subtypes typed generically as
      // TView* (see TMapUberPicture.h's categoryPages[] comment for the evidence); the
      // civilian page is a real TCivToolbar, so this is a legitimate downcast, not a
      // cross-hierarchy type pun.
      static_cast<TCivToolbar*>(
          mapUberPicture->categoryPages[mapUberPicture->activeUnitCategoryIndex96])
          ->RefreshCivilianCommandPanelForSelection(entryContext);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004d2cf0
void TCivMgr::QueueImmediateCivilianCommandAndCycleSelection(int commandType) {
  TCivUnit* entry = this->selectedEntry;
  if (entry != nullptr) {
    entry->SetOrderModeSlot34(commandType, 0);
  }

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
  }
}

// FUNCTION: IMPERIALISM 0x004d2d30
void TCivMgr::ShowDisbandCivilianConfirmationDialog() {
  TCivUnit* entry = this->selectedEntry;
  if (entry == nullptr) {
    return;
  }

  CString titleText;
  CString confirmText;
  g_pSimMgr->GetString(0x274d, 3, &titleText);
  short confirmStringOffset = 4;
  if (entry->orderType == 7) {
    confirmStringOffset = 5;
  }
  g_pSimMgr->GetString(0x274d, confirmStringOffset, &confirmText);

  char confirmed = g_pUiRuntimeContext->ModalMessage(4, titleText, confirmText,
                                                     g_ptCivilianOrderModalMessage, 2, 1);
  if (confirmed == 0) {
    return;
  }

  short tileIndex = entry->tileIndex06;
  if (entry->orderType == 7) {
    g_pInterNationEventQueueManager->QueueInterNationEventType11(g_pSimMgr->GetActiveNationId(), 0,
                                                                 0);
  }
  entry->ResetCivWorkOrderAndRefreshCounters();

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->DispatchSelectedTileToSubviewsAndSyncTradeToolState(tileIndex);
  }
  mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
  }
}

// FUNCTION: IMPERIALISM 0x004d2ef0
bool TCivMgr::TryQueueCivilianMoveOrderToTile(short nTileIndex) {
  char canAssign = this->CanAssignCivilianOrderToTile(nTileIndex);
  if (canAssign != 0) {
    TCivUnit* entry = this->selectedEntry;
    entry->SetOrderModeSlot34(1, entry->tileIndex06);
    g_pSfxPlaybackSystem->PlaySoundEffect(9000, 0, 1);
    this->RelinkCivilianOrderTileAndInvalidateMapTiles(nTileIndex, entry);
  }
  return canAssign != 0;
}

// FUNCTION: IMPERIALISM 0x004d2f60
char TCivMgr::CanAssignCivilianOrderToTile(short nTileIndex) {
  TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[nTileIndex];
  short tileTerrainClass = tile->ownerNationTag04;
  TCivUnit* entry = this->selectedEntry;
  if ((entry->tileIndex06 != nTileIndex) && (tile->gateFlag != 0) &&
      (((tile->activeFlags1c & 1) == 0) || (entry->orderType == 4))) {
    if (tileTerrainClass < 7) {
      return tileTerrainClass == entry->field_18;
    }
    if (g_apTerrainTypeDescriptorTable[tileTerrainClass]->encodedNationSlot == -1) {
      short compatibility = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
          entry->field_18, tileTerrainClass);
      if ((compatibility == 2) && (entry->orderType != 4)) {
        return 1;
      }
    } else if (g_apTerrainTypeDescriptorTable[tileTerrainClass]->IsEncodedNationSlotMinus200Equal(
                   entry->field_18) &&
               (entry->orderType != 4)) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d3070
void TCivMgr::HandleCivilianReportDecision(TCivUnit* pCivilianOrderEntry) {
  if (g_pUiRuntimeContext->ShowCivilianReportDialogAndReturnConfirm(pCivilianOrderEntry)) {
    return;
  }

  short targetTileIndex = pCivilianOrderEntry->tileIndex06;
  short subtypeOrTargetProvince = pCivilianOrderEntry->field_C;
  int refundAmount = 0;
  TGreatPower* ownerNationState = g_apNationStates[pCivilianOrderEntry->field_18];

  switch (pCivilianOrderEntry->orderType) {
  case 5: {
    unsigned char terrainType = g_pGlobalMapState->terrainStateTable[targetTileIndex].terrainType00;
    refundAmount = g_adwEngineerRailBuildCostByTerrainType[terrainType];
    g_pGlobalMapState->ApplyEngineerRailCostDeltaForConnectedTiles(
        targetTileIndex, subtypeOrTargetProvince, pCivilianOrderEntry->field_18);
    break;
  }
  case 6:
    refundAmount = 2000;
    break;
  case 7:
    refundAmount = 3000;
    break;
  case 10: {
    char useHighNibble = ((subtypeOrTargetProvince == 0) || (subtypeOrTargetProvince == 8)) ? 1 : 0;
    unsigned char costClass =
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetTileIndex, useHighNibble);
    refundAmount = g_adwCivilianWorkOrderCostByClass[costClass];
    break;
  }
  case 12: {
    short cityIndex = g_pGlobalMapState->terrainStateTable[targetTileIndex].cityRecordIndex;
    unsigned char fortLevel = g_pGlobalMapState->cityScoreTable[cityIndex].fortLevel03;
    refundAmount = g_awEngineerFortBuildCostByLevel[fortLevel];
    break;
  }
  case 13:
    refundAmount = g_pGlobalMapState->CalculateDeveloperTilePurchaseCost(targetTileIndex);
    break;
  }

  ownerNationState->treasuryValue10 += refundAmount;
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(reinterpret_cast<int>(pCivilianOrderEntry));

  pCivilianOrderEntry->SetOrderModeSlot34(0, subtypeOrTargetProvince);
  if ((subtypeOrTargetProvince != 0) && (subtypeOrTargetProvince != -1)) {
    this->RelinkCivilianOrderTileAndInvalidateMapTiles(subtypeOrTargetProvince,
                                                       pCivilianOrderEntry);
  }

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->SetMapInteractionMode(0);
  }
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();

  this->selectedEntry = pCivilianOrderEntry;
  this->DispatchSelectedUnitToGlobalMapStateHandler(pCivilianOrderEntry);
  if (pCivilianOrderEntry != nullptr) {
    pCivilianOrderEntry->VTableSlot10(pCivilianOrderEntry->tileIndex06);

    TMapUberPicture* invalidateTarget = g_pUiRuntimeContext->mapUberPictureF0;
    if (invalidateTarget != nullptr) {
      invalidateTarget->InvalidateTileMarkerChain(pCivilianOrderEntry->tileIndex06);
    }

    TMapUberPicture* refreshTarget = g_pUiRuntimeContext->mapUberPictureF0;
    if (refreshTarget != nullptr) {
      // Same downcast as TCivMgr::SetActiveCivilianSelection -- categoryPages[civilian] is
      // a real TCivToolbar (see TMapUberPicture.h's categoryPages[] comment).
      static_cast<TCivToolbar*>(
          refreshTarget->categoryPages[refreshTarget->activeUnitCategoryIndex96])
          ->RefreshCivilianCommandPanelForSelection(pCivilianOrderEntry);
    }
  }

  if (mapUberPicture != nullptr) {
    mapUberPicture->NotifySubviewOfSelectedTile(pCivilianOrderEntry->tileIndex06);
  }
}

// FUNCTION: IMPERIALISM 0x004d3310
bool TCivMgr::QueueCivilianWorkOrderWithCostCheck(short nTileIndex) {
  TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  int budget = activeNation->diplomacyBudgetBase / 10 + activeNation->treasuryValue10;
  if (budget < 0) {
    budget = 0;
  }

  char useHighNibble = (selectedEntry->orderType == 0 || selectedEntry->orderType == 8) ? 1 : 0;
  unsigned char costClass =
      g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(nTileIndex, useHighNibble);
  int cost = g_adwCivilianWorkOrderCostByClass[costClass];

  if (budget < cost) {
    CString costText;
    g_pSimMgr->FormatIntegerString(cost, &costText);
    CString templateText;
    g_pSimMgr->GetString(0x2745, 8, &templateText);
    CString finalMessage;
    scanBracketExpressions(g_pSimMgr, &finalMessage, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(costText));
    g_pUiRuntimeContext->ModalMessage(finalMessage, g_ptCivilianOrderModalMessage, 2, 0);
    return false;
  }

  selectedEntry->SetOrderModeSlot34(10, selectedEntry->tileIndex06);
  this->RelinkCivilianOrderTileAndInvalidateMapTiles(nTileIndex,
                                                     g_pSelectedCivilianOrderState->selectedEntry);

  static const short kOrderQueuedSfxByOrderType[9] = {0x232d, 0, 0x2332, 0x2331, 0,
                                                      0x2333, 0, 0x2335, 0x2339};
  short sfxCode = kOrderQueuedSfxByOrderType[selectedEntry->orderType];
  if (sfxCode != 0) {
    g_pSfxPlaybackSystem->PlaySoundEffect(sfxCode, 0, 1);
  }

  unsigned int feedbackStartTick = GetTickCountDiv16();
  while (true) {
    PumpUiMessagesAndBackgroundTasks(1);
    unsigned int feedbackNowTick = GetTickCountDiv16();
    if (feedbackNowTick < feedbackStartTick) {
      break;
    }
    if (feedbackNowTick - feedbackStartTick >= 0x1e) {
      break;
    }
  }

  selectedEntry->completionMarker26 = sfxCode;
  g_apNationStates[g_pSimMgr->GetActiveNationId()]->AddToNationMetricAtField10(-cost);
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
  return true;
}

// FUNCTION: IMPERIALISM 0x004d3a60
bool TCivMgr::HandleEngineerConstructionAction(short nTileIndex) {
  TCivUnit* pCiv = this->selectedEntry;
  if (pCiv == nullptr) {
    return false;
  }

  bool actionFinalized = false;
  bool refreshPanel = false;

  if (nTileIndex == pCiv->tileIndex06) {
    int choice = g_pUiRuntimeContext->ShowConstructionOptionsDialog();
    if (choice == 0x666f7274) { // 'fort'
      short cityIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
      int fortLevel = g_pGlobalMapState->cityScoreTable[cityIndex].fortLevel03;
      short cost = g_awEngineerFortBuildCostByLevel[fortLevel];

      short nationId = g_pSimMgr->GetActiveNationId();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue10;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < cost) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pSimMgr->FormatIntegerString(cost, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= cost;
        pCiv->SetOrderModeSlot34(6, pCiv->tileIndex06);
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232c, 0, 1);
        actionFinalized = true;
      }
    } else if (choice == 0x706f7274) { // 'port'
      short nationId = g_pSimMgr->GetActiveNationId();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue10;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < 3000) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pSimMgr->FormatIntegerString(3000, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= 3000;
        pCiv->SetOrderModeSlot34(7, pCiv->tileIndex06);
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0->InvalidateTileMarkerChain(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232b, 0, 1);
        actionFinalized = true;
      }
    } else if (choice == 0x7261696c) { // 'rail'
      short nationId = g_pSimMgr->GetActiveNationId();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue10;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < 2000) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pSimMgr->FormatIntegerString(2000, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= 2000;
        pCiv->SetOrderModeSlot34(12, pCiv->tileIndex06);
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0->InvalidateTileMarkerChain(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232a, 0, 1);
        actionFinalized = true;
      }
    }
  } else { // adjacent tile click
    int terrainType = g_pGlobalMapState->terrainStateTable[nTileIndex].terrainType00;
    int cost = g_adwEngineerRailBuildCostByTerrainType[terrainType];

    short nationId = g_pSimMgr->GetActiveNationId();
    int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
               g_apNationStates[nationId]->treasuryValue10;
    int availableCash = (cash < 0) ? 0 : cash;

    if (availableCash < cost) {
      CString pszFormattedText;
      CString pszTemplateText;
      CString costString;

      g_pSimMgr->FormatIntegerString(cost, &costString);
      g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
      scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                             static_cast<LPCSTR>(costString));

      g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
    } else {
      short nationId = g_pSimMgr->GetActiveNationId();
      g_apNationStates[nationId]->treasuryValue10 -= cost;
      g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(pCiv->tileIndex06, nTileIndex,
                                                                pCiv->field_18);
      pCiv->SetOrderModeSlot34(5, pCiv->tileIndex06);
      g_pSfxPlaybackSystem->PlaySoundEffect(0x2329, 0, 1);
      actionFinalized = true;
      refreshPanel = true;
    }
  }

  if (actionFinalized) {
    this->RelinkCivilianOrderTileAndInvalidateMapTiles(nTileIndex, pCiv);

    int startTick = GetTickCountDiv16();
    while (true) {
      PumpUiMessagesAndBackgroundTasks(1);
      int now = GetTickCountDiv16();
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
                                                           TCivUnit* pCivOrderEntry) {}
