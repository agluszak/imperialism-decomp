#include "game/TCivMgr.h"

#include "game/TAmbitApplication.h"
#include "decomp_types.h"
#include "game/CIterator.h"
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
#include "game/TSortedList.h"
#include "game/TGreatPower.h"
#include "game/THelpMgr.h"
#include "game/TLandSaleEvent.h"
#include "game/TCivToolbar.h"
#include "game/TNewsMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TMapMgr.h"
#include "game/TMultiplayerMgr.h"
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

// Applies the world-state mutation for a completed civilian work order (order->unitOrder, an
// inherited UnitOrder distinct from TUnit's own `orderType` short, holds this

// FUNCTION: IMPERIALISM 0x004d20c0
void TCivMgr::ICivMgr() {}

// FUNCTION: IMPERIALISM 0x004d20e0
void TCivMgr::ClearCivilianSelectionHighlightsForNation(short nationId) {
  TSortedList* civilianList = g_apNationStates[nationId]->trackedObjectList;
  int civilianCount = civilianList->GetCount();
  for (short ordinal = 1; ordinal <= civilianCount; ++ordinal) {
    TCivUnit* civilian = static_cast<TCivUnit*>(civilianList->GetEntryByOrdinal(ordinal));
    if (civilian->unitOrder == static_cast<UnitOrder>(3)) {
      civilian->SetOrders(kUnitOrderIdle, -1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004d2160
TCivUnit* TCivMgr::SelectFirstAvailableCivilianForNation(short nationId) {
  TSortedList* civilianList = g_apNationStates[nationId]->trackedObjectList;
  int civilianCount = civilianList->GetCount();
  TCivUnit* candidate = nullptr;
  for (short ordinal = 1; ordinal <= civilianCount; ++ordinal) {
    candidate = static_cast<TCivUnit*>(civilianList->GetEntryByOrdinal(ordinal));
    if (candidate->unitOrder == kUnitOrderIdle) {
      break;
    }
    candidate = nullptr;
  }

  if (candidate != nullptr) {
    this->DispatchSelectedUnitToGlobalMapStateHandler(candidate);
  }
  this->selectedEntry = candidate;

  if (candidate != nullptr && candidate->completionMarker26 != -1) {
    g_pSfxPlaybackSystem->PlaySoundEffect(candidate->completionMarker26, 0, 1);
    if (g_pSimMgr->difficultyLevel == 0) {
      g_pHelpMgr->TryShowCivilianCompletionMilestoneNotification(candidate);
    }
    candidate->completionMarker26 = -1;
  }
  return candidate;
}

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
    return (pClickedTileUnit->unitOrder != kUnitOrderIdle) ? 10 : 2;
  }

  if (IsMappedShortcutKeyPressed(2)) {
    return this->CanAssignCivilianOrderToTile(nTileIndex) ? 3 : 1;
  }

  TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[nTileIndex];
  if (tile->recruitSearchVisited0e == 0) {
    CivilianUnitKind unitKind = selectedEntry->GetCivilianUnitKind();
    if (unitKind == kCivilianUnitProspector) {
      return 8;
    }
    if (unitKind == kCivilianUnitEngineer) {
      short homeTile = selectedEntry->tileIndex06;
      if (nTileIndex == homeTile) {
        return 4;
      }
      StrategicHexDirectionStorage dir = TMapMgr::GetDirectionFrom(homeTile, nTileIndex);
      if ((dir == 1) || (dir == 4)) {
        return 5;
      }
      if ((dir == 0) || (dir == 3)) {
        return 6;
      }
      return 7;
    }
    if (unitKind == kCivilianUnitDeveloper) {
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
    mapUberPicture->InvalidateTile(entryContext->tileIndex06);
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
void TCivMgr::OrderAndCycle(UnitOrder order) {
  TCivUnit* entry = this->selectedEntry;
  if (entry != nullptr) {
    entry->SetOrders(order, 0);
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
  if (entry->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
    confirmStringOffset = 5;
  }
  g_pSimMgr->GetString(0x274d, confirmStringOffset, &confirmText);

  char confirmed = g_pUiRuntimeContext->ModalMessage(4, titleText, confirmText,
                                                     g_ptCivilianOrderModalMessage, 2, 1);
  if (confirmed == 0) {
    return;
  }

  short tileIndex = entry->tileIndex06;
  if (entry->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
    g_pInterNationEventQueueManager->QueueInterNationEventType11(g_pSimMgr->GetActiveNationId(), 0,
                                                                 0);
  }
  entry->ResetCivWorkOrderAndRefreshCounters();

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->RedrawTile(tileIndex);
  }
  mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapUberPicture != nullptr) {
    mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
  }
}

// FUNCTION: IMPERIALISM 0x004d2ef0
bool TCivMgr::TryQueueCivilianMoveOrderToTile(short nTileIndex) {
  bool canAssign = this->CanAssignCivilianOrderToTile(nTileIndex);
  if (canAssign) {
    TCivUnit* entry = this->selectedEntry;
    entry->SetOrders(kUnitOrderRedeploy, entry->tileIndex06);
    g_pSfxPlaybackSystem->PlaySoundEffect(9000, 0, 1);
    this->RelinkCivilianOrderTileAndInvalidateMapTiles(nTileIndex, entry);
  }
  return canAssign;
}

// FUNCTION: IMPERIALISM 0x004d2f60
bool TCivMgr::CanAssignCivilianOrderToTile(short nTileIndex) {
  TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[nTileIndex];
  short tileTerrainClass = tile->ownerNationTag04;
  TCivUnit* entry = this->selectedEntry;
  if ((entry->tileIndex06 != nTileIndex) && (tile->gateFlag != 0) &&
      (((tile->activeFlags1c & 1) == 0) ||
       (entry->orderType == EncodeCivilianUnitKind(kCivilianUnitEngineer)))) {
    if (tileTerrainClass < 7) {
      return tileTerrainClass == entry->field_18;
    }
    if (g_apTerrainTypeDescriptorTable[tileTerrainClass]->encodedNationSlot == -1) {
      short compatibility = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
          entry->field_18, tileTerrainClass);
      if ((compatibility == 2) &&
          (entry->orderType != EncodeCivilianUnitKind(kCivilianUnitEngineer))) {
        return 1;
      }
    } else if (g_apTerrainTypeDescriptorTable[tileTerrainClass]->IsEncodedNationSlotMinus200Equal(
                   entry->field_18) &&
               (entry->orderType != EncodeCivilianUnitKind(kCivilianUnitEngineer))) {
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

  switch (pCivilianOrderEntry->unitOrder) {
  case kUnitOrderLayRail: {
    StrategicTerrainKind terrainKind =
        g_pGlobalMapState->terrainStateTable[targetTileIndex].GetTerrainKind();
    refundAmount = g_adwEngineerRailBuildCostByTerrainType[terrainKind];
    g_pGlobalMapState->ApplyEngineerRailCostDeltaForConnectedTiles(
        targetTileIndex, subtypeOrTargetProvince, pCivilianOrderEntry->field_18);
    break;
  }
  case kUnitOrderBuildDepot:
    refundAmount = 2000;
    break;
  case kUnitOrderBuildPort:
    refundAmount = 3000;
    break;
  case kUnitOrderDevelopResource: {
    char useHighNibble = ((subtypeOrTargetProvince == 0) || (subtypeOrTargetProvince == 8)) ? 1 : 0;
    unsigned char costClass =
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetTileIndex, useHighNibble);
    refundAmount = g_adwCivilianWorkOrderCostByClass[costClass];
    break;
  }
  case kUnitOrderBuildFort: {
    short cityIndex = g_pGlobalMapState->terrainStateTable[targetTileIndex].cityRecordIndex;
    unsigned char fortLevel = g_pGlobalMapState->cityScoreTable[cityIndex].fortLevel03;
    refundAmount = g_awEngineerFortBuildCostByLevel[fortLevel];
    break;
  }
  case kUnitOrderPurchaseLand:
    refundAmount = g_pGlobalMapState->CalculateDeveloperTilePurchaseCost(targetTileIndex);
    break;
  }

  ownerNationState->treasuryValue10 += refundAmount;
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(reinterpret_cast<int>(pCivilianOrderEntry));

  pCivilianOrderEntry->SetOrders(kUnitOrderIdle, subtypeOrTargetProvince);
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
      invalidateTarget->InvalidateTile(pCivilianOrderEntry->tileIndex06);
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
    mapUberPicture->NoticeTile(pCivilianOrderEntry->tileIndex06);
  }
}

// FUNCTION: IMPERIALISM 0x004d3310
bool TCivMgr::QueueCivilianWorkOrderWithCostCheck(short nTileIndex) {
  TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  int budget = activeNation->diplomacyBudgetBase / 10 + activeNation->treasuryValue10;
  if (budget < 0) {
    budget = 0;
  }

  char useHighNibble = (selectedEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner) ||
                        selectedEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitDriller))
                           ? 1
                           : 0;
  unsigned char costClass =
      g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(nTileIndex, useHighNibble);
  int cost = g_adwCivilianWorkOrderCostByClass[costClass];

  if (budget < cost) {
    CString costText;
    g_pSimMgr->NumToCurrency(cost, &costText);
    CString templateText;
    g_pSimMgr->GetString(0x2745, 8, &templateText);
    CString finalMessage;
    scanBracketExpressions(g_pSimMgr, &finalMessage, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(costText));
    g_pUiRuntimeContext->ModalMessage(finalMessage, g_ptCivilianOrderModalMessage, 2, 0);
    return false;
  }

  selectedEntry->SetOrders(kUnitOrderDevelopResource, selectedEntry->tileIndex06);
  this->RelinkCivilianOrderTileAndInvalidateMapTiles(nTileIndex,
                                                     g_pSelectedCivilianOrderState->selectedEntry);

  static const short kOrderQueuedSfxByOrderType[9] = {0x232d, 0, 0x2332, 0x2331, 0,
                                                      0x2333, 0, 0x2335, 0x2339};
  short sfxCode = kOrderQueuedSfxByOrderType[selectedEntry->GetCivilianUnitKind()];
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
  g_apNationStates[g_pSimMgr->GetActiveNationId()]->AddToTreasury(-cost);
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
  return true;
}

// FUNCTION: IMPERIALISM 0x004d3610
bool TCivMgr::PromptAndQueueDeveloperTilePurchaseOrder(short nTileIndex) {
  TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  int availableCash = activeNation->diplomacyBudgetBase / 100 + activeNation->treasuryValue10;
  if (availableCash < 0) {
    availableCash = 0;
  }
  int purchaseCost = g_pGlobalMapState->CalculateDeveloperTilePurchaseCost(nTileIndex);

  CString titleText;
  CString templateText;
  CString formattedText;
  CString costText;
  CString cityName;
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
  g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
  g_pSimMgr->GetString(0x274d, 0, &titleText);
  g_pSimMgr->NumToCurrency(purchaseCost, &costText);

  if (availableCash >= purchaseCost) {
    // Mac Strings.rsrc: "the governor of [1] will sell us this land for [2]".
    g_pSimMgr->GetString(0x274d, 1, &templateText);
    scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(cityName), static_cast<LPCSTR>(costText));
    if (g_pUiRuntimeContext->ModalMessage(4, titleText, formattedText,
                                          g_ptCivilianOrderModalMessage, 0, 1) != 0) {
      selectedEntry->SetOrders(kUnitOrderPurchaseLand, selectedEntry->tileIndex06);
      this->RelinkCivilianOrderTileAndInvalidateMapTiles(
          nTileIndex, g_pSelectedCivilianOrderState->selectedEntry);
      g_pSfxPlaybackSystem->PlaySoundEffect(0x2335, 0, 1);
      g_apNationStates[g_pSimMgr->GetActiveNationId()]->AddToTreasury(-purchaseCost);
      g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();

      unsigned int feedbackStartTick = GetTickCountDiv16();
      while (true) {
        PumpUiMessagesAndBackgroundTasks(1);
        unsigned int feedbackNowTick = GetTickCountDiv16();
        if (feedbackNowTick < feedbackStartTick || feedbackNowTick - feedbackStartTick >= 0x1e) {
          break;
        }
      }
      return true;
    }
  } else {
    // Mac Strings.rsrc: "the governor of [1] has set the price ... we cannot afford".
    g_pSimMgr->GetString(0x274d, 2, &templateText);
    scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(cityName), static_cast<LPCSTR>(costText));
    g_pUiRuntimeContext->ModalMessage(3, titleText, formattedText, g_ptCivilianOrderModalMessage, 0,
                                      0);
  }
  return false;
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

        g_pSimMgr->NumToCurrency(cost, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= cost;
        pCiv->SetOrders(kUnitOrderBuildDepot, pCiv->tileIndex06);
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

        g_pSimMgr->NumToCurrency(3000, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= 3000;
        pCiv->SetOrders(kUnitOrderBuildPort, pCiv->tileIndex06);
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0->InvalidateTile(nTileIndex);
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

        g_pSimMgr->NumToCurrency(2000, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetActiveNationId();
        g_apNationStates[nationId]->treasuryValue10 -= 2000;
        pCiv->SetOrders(kUnitOrderBuildFort, pCiv->tileIndex06);
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0->InvalidateTile(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232a, 0, 1);
        actionFinalized = true;
      }
    }
  } else { // adjacent tile click
    StrategicTerrainKind terrainKind =
        g_pGlobalMapState->terrainStateTable[nTileIndex].GetTerrainKind();
    int cost = g_adwEngineerRailBuildCostByTerrainType[terrainKind];

    short nationId = g_pSimMgr->GetActiveNationId();
    int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
               g_apNationStates[nationId]->treasuryValue10;
    int availableCash = (cash < 0) ? 0 : cash;

    if (availableCash < cost) {
      CString pszFormattedText;
      CString pszTemplateText;
      CString costString;

      g_pSimMgr->NumToCurrency(cost, &costString);
      g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
      scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                             static_cast<LPCSTR>(costString));

      g_pUiRuntimeContext->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
    } else {
      short nationId = g_pSimMgr->GetActiveNationId();
      g_apNationStates[nationId]->treasuryValue10 -= cost;
      g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(pCiv->tileIndex06, nTileIndex,
                                                                pCiv->field_18);
      pCiv->SetOrders(kUnitOrderLayRail, pCiv->tileIndex06);
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
// specific completion kind: 5=rail section, 6=depot, 7=port, 8=discovery/prospecting,
// 10=development-tier advance, 12=city/building completion, 13=tile activity byte), then
// dispatches redraw invalidation for the affected tiles/cities when the localized map UI
// is active (g_pSimMgr->multiplayerSessionRole != 0).
// FUNCTION: IMPERIALISM 0x004d4390
void TCivMgr::ApplyCompletedCivWorkOrderToMapState(TCivUnit* order) {
  // Case bodies are written in the original's physical block layout (5, 8, 3, 1, 2, 0, 7 --
  // not ascending case-value order) so MSVC500's jump-table codegen lays them out the same
  // way; the jump table itself (built from the case labels) is unaffected by text order.
  switch (order->unitOrder - kUnitOrderLayRail) {
  case 5: {
    bool selectHighNibble = order->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner) ||
                            order->orderType == EncodeCivilianUnitKind(kCivilianUnitDriller);
    byte result = g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(order->tileIndex06,
                                                                             selectHighNibble);
    g_pGlobalMapState->SetCivilianDevelopmentClassNibble(order->tileIndex06, selectHighNibble,
                                                         static_cast<byte>(result + 1), 1);
    break;
  }
  case 8:
    g_pGlobalMapState->terrainStateTable[order->tileIndex06].secondaryOwnerNationTag18 =
        static_cast<signed char>(order->field_18);
    break;
  case 3: {
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[order->tileIndex06];
    tile.pendingDevelopmentFlag0d |= static_cast<unsigned char>(1 << order->field_18);
    if (g_apNationStates[order->field_18]->diplomacyEligibilityA0 != 0 &&
        g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(order->tileIndex06) != 0) {
      order->completionMarker26 = 0x232f;
    }
    break;
  }
  case 1:
    g_pGlobalMapState->QueueDepotConstructionOrder(order->tileIndex06, order->field_18);
    g_apNationStates[order->field_18]->BuildTransportLinkedInfluenceMap(nullptr);
    order->completionMarker26 = 0x232a;
    break;
  case 2:
    g_pGlobalMapState->QueuePortConstructionOrder(order->tileIndex06, order->field_18);
    g_apNationStates[order->field_18]->BuildTransportLinkedInfluenceMap(nullptr);
    order->completionMarker26 = 0x232b;
    break;
  case 0:
    g_pGlobalMapState->SetHexAdjacencyDirectionFlagsForTilePair(order->field_C, order->tileIndex06,
                                                                order->field_18);
    order->completionMarker26 = 0x2329;
    break;
  case 7:
    g_pGlobalMapState->SetProvinceCapitalTileFlagBit08(
        g_pGlobalMapState->terrainStateTable[order->tileIndex06].cityRecordIndex);
    break;
  default:
    break;
  }

  if (g_pSimMgr->multiplayerSessionRole == 0) {
    return;
  }

  switch (order->unitOrder - kUnitOrderLayRail) {
  case 0:
    DispatchTileRedrawInvalidateEvent(order->field_C);
  case 3:
  case 5:
  case 8:
    DispatchTileRedrawInvalidateEvent(order->tileIndex06);
    return;
  case 1:
  case 2: {
    short neighborBuf[7];
    TMapMgr::GetNeighborTileIDArray(order->tileIndex06, neighborBuf,
                                    g_pGlobalMapState->hexNeighborWrapHorizontally20);
    neighborBuf[6] = order->tileIndex06;
    TTerrainStateRecordView& centerTile = g_pGlobalMapState->terrainStateTable[order->tileIndex06];
    for (int i = 0; i < 7; ++i) {
      short t = neighborBuf[i];
      if (t == -1) {
        continue;
      }
      DispatchTileRedrawInvalidateEvent(t);
      short cityIdx = g_pGlobalMapState->terrainStateTable[t].cityRecordIndex;
      if ((centerTile.activeFlags1c & 3) != 0 && centerTile.gateFlag != 0 && cityIdx != -1) {
        g_pGameFlowState->DispatchCityRedrawInvalidateEvent(cityIdx);
      }
    }
    return;
  }
  case 7: {
    short cityIdx = g_pGlobalMapState->terrainStateTable[order->tileIndex06].cityRecordIndex;
    g_pGameFlowState->DispatchCityRedrawInvalidateEvent(cityIdx);
    DispatchTileRedrawInvalidateEvent(g_pGlobalMapState->cityScoreTable[cityIdx].cityTileIndex04);
    return;
  }
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004d4740
void TCivMgr::ResolveCivilianDisputes() {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    TCivUnit* order = tile.firstCivilianOrder20;
    if (order == 0 || order->nextOnTile == 0) {
      continue;
    }

    TCivUnit* competingOrders[7] = {0};
    int competingCount = 0;
    while (order != 0) {
      if (order->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper) &&
          order->unitOrder == kUnitOrderPurchaseLand) {
        competingOrders[competingCount++] = order;
      }
      order = static_cast<TCivUnit*>(order->nextOnTile);
    }
    if (competingCount <= 1) {
      continue;
    }

    int ownerNationSlot = static_cast<signed char>(tile.ownerNationTag04);
    TCivUnit* winningOrder = competingOrders[0];
    short winningStanding =
        g_pDiplomacyTurnStateManager
            ->relationStandingScoreMatrix79c[winningOrder->field_18 * 0x17 + ownerNationSlot];
    for (int candidateIndex = 1; candidateIndex < competingCount; ++candidateIndex) {
      TCivUnit* candidate = competingOrders[candidateIndex];
      short candidateStanding =
          g_pDiplomacyTurnStateManager
              ->relationStandingScoreMatrix79c[candidate->field_18 * 0x17 + ownerNationSlot];
      if (candidateStanding > winningStanding ||
          (candidateStanding == winningStanding && (rand() & 1) != 0)) {
        winningOrder = candidate;
        winningStanding = candidateStanding;
      }
    }

    for (int orderIndex = 0; orderIndex < competingCount; ++orderIndex) {
      TCivUnit* losingOrder = competingOrders[orderIndex];
      if (losingOrder == winningOrder) {
        continue;
      }

      short losingNationSlot = losingOrder->field_18;
      losingOrder->SetOrders(kUnitOrderIdle, -1);
      g_apNationStates[losingNationSlot]->treasuryValue10 +=
          g_pGlobalMapState->CalculateDeveloperTilePurchaseCost(static_cast<short>(tileIndex));

      if (g_apNationStates[losingNationSlot]->diplomacyEligibilityA0 != 0) {
        TLandSaleEvent* event = new TLandSaleEvent();
        event->ILandSaleEvent(static_cast<short>(tileIndex), winningOrder->field_18);
        g_apNationStates[losingNationSlot]->AddTurnStartEvent(event);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004d49f0
void TCivMgr::ClearNationCivilianActionModesAndCycleSelection(int nationId) {
  CIterator cursor(g_apNationStates[nationId]->trackedObjectList);
  TCivUnit* civilian = static_cast<TCivUnit*>(cursor.Reset());
  while (cursor.More() != 0) {
    if (civilian->unitOrder == static_cast<UnitOrder>(2) ||
        civilian->unitOrder == static_cast<UnitOrder>(3) ||
        civilian->unitOrder == static_cast<UnitOrder>(4)) {
      civilian->SetOrders(kUnitOrderIdle, 0);
    }
    civilian = static_cast<TCivUnit*>(cursor.Advance());
  }

  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapView != 0 && !mapView->HasActiveMapInteractionSelection()) {
    mapView->CycleMapInteractionSelectionAfterHandledClick();
  }
}
