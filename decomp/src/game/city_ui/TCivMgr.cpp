#include "game/nation_domain_types.h"
#include "game/map_domain_types.h"
#include "game/city_ui/TCivMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/gfx/TAmbitApplication.h"
#include "decomp_types.h"
#include "game/ui_core/CIterator.h"
#include "game/app/TAnimator.h"
#include "game/military/TCivUnit.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TSortedList.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/THelpMgr.h"
#include "game/nation/TLandSaleEvent.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map/TMapMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/military/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/pointer_representation.h"
#include "game/ui_core/ui_message_pump.h"

IMPLEMENT_DYNCREATE(TCivMgr, TObject)

// FUNCTION: IMPERIALISM 0x004d2050
TCivMgr::TCivMgr() {}

// FUNCTION: IMPERIALISM 0x004d20a0
TCivMgr::~TCivMgr() {}

// FUNCTION: IMPERIALISM 0x004d20c0
void TCivMgr::ICivMgr() {}

// FUNCTION: IMPERIALISM 0x004d20e0
void TCivMgr::ResetCycle(short nationId) {
  TSortedList* civilianList = g_apNationStates[nationId]->trackedObjectList;
  for (short ordinal = 1; ordinal <= civilianList->GetCount(); ++ordinal) {
    TCivUnit* civilian = static_cast<TCivUnit*>(civilianList->GetEntryByOrdinal(ordinal));
    if (civilian->unitOrder == static_cast<UnitOrder>(3)) {
      civilian->SetOrders(kUnitOrderIdle, -1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004d2160
TCivUnit* TCivMgr::Cycle(short nationId) {
  TSortedList* civilianList = g_apNationStates[nationId]->trackedObjectList;
  int civilianCount = civilianList->GetCount();
  TCivUnit* candidate = NULL;
  for (short ordinal = 1; ordinal <= civilianCount; ++ordinal) {
    candidate = static_cast<TCivUnit*>(civilianList->GetEntryByOrdinal(ordinal));
    if (candidate->unitOrder == kUnitOrderIdle) {
      break;
    }
    candidate = NULL;
  }

  if (candidate != NULL) {
    SetDimming(candidate);
  }
  selectedEntry = candidate;

  if (candidate != NULL && candidate->completionMarker != -1) {
    g_pSfxPlaybackSystem->PlaySoundEffect(candidate->completionMarker, 0, 1);
    if (g_pSimMgr->difficultyLevel == kDifficultyIntroductory) {
      g_pHelpMgr->CheckUnitAdvice(candidate);
    }
    candidate->completionMarker = -1;
  }
  return candidate;
}

// FUNCTION: IMPERIALISM 0x004d2270
void TCivMgr::SetDimming(TCivUnit* pUnitOrderEntry) {
  if (pUnitOrderEntry != NULL) {
    switch (pUnitOrderEntry->orderType) {
    case 1:
      g_pGlobalMapState->DimByProspecting(pUnitOrderEntry);
      return;
    case 4:
      g_pGlobalMapState->DimByEngineering(pUnitOrderEntry);
      return;
    case 2:
    case 3:
    case 5:
      g_pGlobalMapState->DimByCompany(pUnitOrderEntry);
      return;
    case 7:
      g_pGlobalMapState->DimByDevelopment(pUnitOrderEntry);
      return;
    case 0:
    case 8:
      g_pGlobalMapState->DimByMining(pUnitOrderEntry);
      return;
    case 6:
      g_pGlobalMapState->DimByFishing(pUnitOrderEntry);
      return;
    default:
      g_pGlobalMapState->ResetRecruitSearchVisitedState();
      return;
    }
  }
  g_pGlobalMapState->ResetRecruitSearchVisitedState();
}

// FUNCTION: IMPERIALISM 0x004d2380
bool TCivMgr::HandleCivilianTileSelectionOrReportClick(short nTileIndex, short nClickMode) {
  int actionCode = 0;
  short nationId = g_pSimMgr->GetPlayerCountry();
  TCivUnit* clickedEntry = g_pGlobalMapState->GetMyFirstUnit(nTileIndex, nationId);
  if (clickedEntry != NULL) {
    clickedEntry = g_pGlobalMapState->GetMyFirstUnit(nTileIndex, g_pSimMgr->GetPlayerCountry());
    if (clickedEntry->CanBeOrdered()) {
      if (nClickMode == 2 ||
          (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags & 0x20) == 0) {
        actionCode = 2;
      }
    } else {
      actionCode = 10;
    }
  }

  TCivUnit* tileEntry = g_pGlobalMapState->terrainStateTable[nTileIndex].firstCivilianOrder;
  if (actionCode == 2) {
    TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
    if (mapUberPicture == NULL) {
      return false;
    }

    mapUberPicture->SetMapInteractionMode(0);
    selectedEntry = tileEntry;
    SetDimming(tileEntry);
    if (tileEntry != NULL) {
      tileEntry->MoveTo(tileEntry->tileIndex);
      if (g_pViewMgr->mapUberPicture != NULL) {
        g_pViewMgr->mapUberPicture->InvalidateTile(tileEntry->tileIndex);
      }
      mapUberPicture = g_pViewMgr->mapUberPicture;
      if (mapUberPicture != NULL) {
        static_cast<TCivToolbar*>(
            mapUberPicture->categoryPages[mapUberPicture->activeUnitCategoryIndex])
            ->SetSelectedUnit(tileEntry);
      }
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(0x2338, 0, 1);
    return true;
  }
  if (actionCode == 10) {
    InfoBox(tileEntry);
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004d2540
unsigned short TCivMgr::ResolveCivilianTileSelectionOrReportActionCode(short nTileIndex,
                                                                       short nClickMode) {
  CivilianTileActionCodeStorage actionCode = kCivilianTileActionNone;
  TCivUnit* entry = g_pGlobalMapState->GetMyFirstUnit(nTileIndex, g_pSimMgr->GetPlayerCountry());
  if (entry != NULL) {
    entry = g_pGlobalMapState->GetMyFirstUnit(nTileIndex, g_pSimMgr->GetPlayerCountry());
    if (!entry->CanBeOrdered()) {
      actionCode = kCivilianTileActionShowOrderReport;
    } else if (nClickMode == 2 ||
               (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags >> 5 & 1) == 0) {
      actionCode = kCivilianTileActionSelectUnit;
    }
  }
  if (actionCode == kCivilianTileActionSelectUnit) {
    return 0x3f9;
  }
  return (actionCode != kCivilianTileActionShowOrderReport) - 1 & 0x3f3;
}

// FUNCTION: IMPERIALISM 0x004d2610
CivilianTileActionCodeStorage TCivMgr::GetTileAction(short tileIndex, short mode) {
  CivilianTileActionCodeStorage actionCode = kCivilianTileActionNone;
  if (g_pGlobalMapState->GetMyFirstUnit(tileIndex, g_pSimMgr->GetPlayerCountry()) != 0) {
    // The original looks the unit up a second time rather than reusing the first result.
    TCivUnit* unit = g_pGlobalMapState->GetMyFirstUnit(tileIndex, g_pSimMgr->GetPlayerCountry());
    if (!unit->CanBeOrdered()) {
      actionCode = kCivilianTileActionShowOrderReport;
    } else if (mode == 2 ||
               ((g_pGlobalMapState->terrainStateTable[tileIndex].activeFlags >> 5) & 1) == 0) {
      return kCivilianTileActionSelectUnit;
    }
  }
  return actionCode;
}

// FUNCTION: IMPERIALISM 0x004d26d0
bool TCivMgr::HandleCivilianTileOrderAction(short nTileIndex, short nInputHint) {
  bool handled = false;
  CivilianTileActionCodeStorage actionCode =
      ResolveCivilianTileOrderActionCode(nTileIndex, nInputHint);
  switch (actionCode) {
  case kCivilianTileActionSelectUnit: {
    TCivUnit* tileEntry = g_pGlobalMapState->terrainStateTable[nTileIndex].firstCivilianOrder;
    selectedEntry = tileEntry;
    SetDimming(tileEntry);
    if (tileEntry != NULL) {
      tileEntry->MoveTo(tileEntry->tileIndex);
      TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
      if (mapUberPicture != NULL) {
        mapUberPicture->InvalidateTile(tileEntry->tileIndex);
      }
      mapUberPicture = g_pViewMgr->mapUberPicture;
      if (mapUberPicture != NULL) {
        static_cast<TCivToolbar*>(
            mapUberPicture->categoryPages[mapUberPicture->activeUnitCategoryIndex])
            ->SetSelectedUnit(tileEntry);
      }
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(0x2338, 0, 1);
    return false;
  }
  case kCivilianTileActionMoveUnit:
    handled = CanDeployUnit(nTileIndex);
    if (handled) {
      selectedEntry->SetOrders(kUnitOrderRedeploy, selectedEntry->tileIndex);
      g_pSfxPlaybackSystem->PlaySoundEffect(0x2328, 0, 1);
      MoveAndRedrawUnit(nTileIndex, selectedEntry);
    }
    return handled;
  case kCivilianTileActionEngineerSameTile:
  case kCivilianTileActionEngineerDirection14:
  case kCivilianTileActionEngineerDirection03:
  case kCivilianTileActionEngineerDirection25:
    return EngineerClick(nTileIndex);
  case kCivilianTileActionProspect:
    selectedEntry->SetOrders(kUnitOrderProspect, selectedEntry->tileIndex);
    MoveAndRedrawUnit(nTileIndex, selectedEntry);
    g_pSfxPlaybackSystem->PlaySoundEffect(0x232e, 0, 1);
    {
      unsigned int startTick = GetTickCountDiv16();
      unsigned int nowTick;
      do {
        PumpUiMessagesAndBackgroundTasks(1);
        nowTick = GetTickCountDiv16();
        if (nowTick < startTick) {
          return true;
        }
      } while (nowTick - startTick < 0x1e);
    }
    return true;
  case kCivilianTileActionDevelopResource:
    return ImprovementClick(nTileIndex);
  case kCivilianTileActionShowOrderReport:
    InfoBox(g_pGlobalMapState->terrainStateTable[nTileIndex].firstCivilianOrder);
    return false;
  case kCivilianTileActionPurchaseLand:
    handled = PurchaseClick(nTileIndex);
    break;
  }
  return handled;
}

// FUNCTION: IMPERIALISM 0x004d2930
unsigned short TCivMgr::LookupCivilianTileOrderCursorTokenByActionIndex(short nTileIndex,
                                                                        short nInputHint) {
  CivilianTileActionCodeStorage actionCode =
      ResolveCivilianTileOrderActionCode(nTileIndex, nInputHint);
  return g_civilianTileOrderCursorTokenTable[actionCode];
}

// FUNCTION: IMPERIALISM 0x004d2960
CivilianTileActionCodeStorage TCivMgr::ResolveCivilianTileOrderActionCode(short nTileIndex,
                                                                          short nInputHint) {
  short nationId = g_pSimMgr->GetPlayerCountry();
  TCivUnit* pClickedTileUnit = g_pGlobalMapState->GetMyFirstUnit(nTileIndex, nationId);

  if ((g_pGlobalMapState->hexNeighborWrapHorizontally != 0) &&
      ((nTileIndex % kStrategicMapColumns == 0) || (nTileIndex % kStrategicMapColumns == 0x6b))) {
    return kCivilianTileActionBlocked;
  }

  TCivUnit* selectedEntry = this->selectedEntry;
  if (selectedEntry == NULL) {
    nationId = g_pSimMgr->GetPlayerCountry();
    TCivUnit* pOwnedCivilianEntry = g_pGlobalMapState->GetMyFirstUnit(nTileIndex, nationId);
    if (pOwnedCivilianEntry == NULL) {
      return kCivilianTileActionNone;
    }
    if (!g_pGlobalMapState->GetMyFirstUnit(nTileIndex, g_pSimMgr->GetPlayerCountry())
             ->CanBeOrdered()) {
      return kCivilianTileActionShowOrderReport;
    }
    if ((nInputHint != 2) &&
        (((g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags >> 5) & 1) != 0)) {
      return kCivilianTileActionNone;
    }
    return kCivilianTileActionSelectUnit;
  }

  if ((pClickedTileUnit != NULL) && (pClickedTileUnit != selectedEntry)) {
    return (pClickedTileUnit->unitOrder != kUnitOrderIdle) ? kCivilianTileActionShowOrderReport
                                                           : kCivilianTileActionSelectUnit;
  }

  if (IsMappedShortcutKeyPressed(2)) {
    if (CanDeployUnit(nTileIndex)) {
      return kCivilianTileActionMoveUnit;
    }
    return kCivilianTileActionBlocked;
  }

  TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[nTileIndex];
  if (tile->recruitSearchVisited == 0) {
    CivilianUnitKind unitKind = selectedEntry->GetCivilianUnitKind();
    if (unitKind == kCivilianUnitProspector) {
      return kCivilianTileActionProspect;
    }
    if (unitKind == kCivilianUnitEngineer) {
      short homeTile = selectedEntry->tileIndex;
      if (nTileIndex == homeTile) {
        return kCivilianTileActionEngineerSameTile;
      }
      StrategicHexDirectionStorage dir = TMapMgr::GetDirectionFrom(homeTile, nTileIndex);
      if ((dir == 1) || (dir == 4)) {
        return kCivilianTileActionEngineerDirection14;
      }
      if ((dir == 0) || (dir == 3)) {
        return kCivilianTileActionEngineerDirection03;
      }
      return kCivilianTileActionEngineerDirection25;
    }
    if (unitKind == kCivilianUnitDeveloper) {
      return kCivilianTileActionPurchaseLand;
    }
    return kCivilianTileActionDevelopResource;
  }

  TCivUnit* orderAtTile = tile->firstCivilianOrder;
  if (orderAtTile != NULL) {
    nationId = g_pSimMgr->GetPlayerCountry();
    if (orderAtTile->ownerNationSlot == nationId) {
      return orderAtTile->CanBeOrdered() ? kCivilianTileActionSelectUnit
                                         : kCivilianTileActionShowOrderReport;
    }
  }
  if (CanDeployUnit(nTileIndex)) {
    return kCivilianTileActionMoveUnit;
  }
  return kCivilianTileActionBlocked;
}

// FUNCTION: IMPERIALISM 0x004d2c60
void TCivMgr::SelectUnit(TCivUnit* entryContext, bool refreshCommandPanel) {
  selectedEntry = entryContext;
  SetDimming(entryContext);
  if (entryContext == NULL) {
    return;
  }

  entryContext->MoveTo(entryContext->tileIndex);

  TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
  if (mapUberPicture != NULL) {
    mapUberPicture->InvalidateTile(entryContext->tileIndex);
  }

  if (refreshCommandPanel) {
    mapUberPicture = g_pViewMgr->mapUberPicture;
    if (mapUberPicture != NULL) {
      static_cast<TCivToolbar*>(
          mapUberPicture->categoryPages[mapUberPicture->activeUnitCategoryIndex])
          ->SetSelectedUnit(entryContext);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004d2cf0
void TCivMgr::OrderAndCycle(UnitOrder order) {
  TCivUnit* entry = selectedEntry;
  if (entry != NULL) {
    entry->SetOrders(order, 0);
  }

  TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
  if (mapUberPicture != NULL) {
    mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
  }
}

// FUNCTION: IMPERIALISM 0x004d2d30
void TCivMgr::DisbandSelected() {
  TCivUnit* entry = selectedEntry;
  if (entry == NULL) {
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

  bool confirmed =
      g_pViewMgr->ModalMessage(4, titleText, confirmText, g_ptCivilianOrderModalMessage, 2, 1);
  if (confirmed == 0) {
    return;
  }

  short tileIndex = entry->tileIndex;
  if (entry->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
    g_pNewsMgr->AddMiscEvent(g_pSimMgr->GetPlayerCountry(), 0, false);
  }
  entry->ClearOrders();

  TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
  if (mapUberPicture != NULL) {
    mapUberPicture->RedrawTile(tileIndex);
  }
  mapUberPicture = g_pViewMgr->mapUberPicture;
  if (mapUberPicture != NULL) {
    mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
  }
}

// FUNCTION: IMPERIALISM 0x004d2ef0
bool TCivMgr::TryQueueCivilianMoveOrderToTile(short nTileIndex) {
  bool canAssign = CanDeployUnit(nTileIndex);
  if (canAssign) {
    TCivUnit* entry = selectedEntry;
    entry->SetOrders(kUnitOrderRedeploy, entry->tileIndex);
    g_pSfxPlaybackSystem->PlaySoundEffect(9000, 0, 1);
    MoveAndRedrawUnit(nTileIndex, entry);
  }
  return canAssign;
}

// FUNCTION: IMPERIALISM 0x004d2f60
bool TCivMgr::CanDeployUnit(short nTileIndex) {
  TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[nTileIndex];
  short tileTerrainClass = tile->ownerNationTag;
  TCivUnit* entry = selectedEntry;
  if ((entry->tileIndex != nTileIndex) && (tile->gateFlag != 0) &&
      (((tile->activeFlags & 1) == 0) ||
       (entry->orderType == EncodeCivilianUnitKind(kCivilianUnitEngineer)))) {
    if (tileTerrainClass < 7) {
      return tileTerrainClass == entry->ownerNationSlot;
    }
    if (g_apTerrainTypeDescriptorTable[tileTerrainClass]->encodedNationSlot == -1) {
      short compatibility =
          g_pDiplomacyTurnStateManager->GetEmbassyStatus(entry->ownerNationSlot, tileTerrainClass);
      if ((compatibility == 2) &&
          (entry->orderType != EncodeCivilianUnitKind(kCivilianUnitEngineer))) {
        return true;
      }
    } else if (g_apTerrainTypeDescriptorTable[tileTerrainClass]->IsColonyOf(
                   entry->ownerNationSlot) &&
               (entry->orderType != EncodeCivilianUnitKind(kCivilianUnitEngineer))) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004d3070
void TCivMgr::InfoBox(TCivUnit* pCivilianOrderEntry) {
  if (g_pViewMgr->MakeCivInfoWindow(pCivilianOrderEntry)) {
    return;
  }

  short targetTileIndex = pCivilianOrderEntry->tileIndex;
  short subtypeOrTargetProvince = pCivilianOrderEntry->orderTargetIndex;
  int refundAmount = 0;
  TGreatPower* ownerNationState = g_apNationStates[pCivilianOrderEntry->ownerNationSlot];

  switch (pCivilianOrderEntry->unitOrder) {
  case kUnitOrderLayRail: {
    StrategicTerrainKind terrainKind =
        g_pGlobalMapState->terrainStateTable[targetTileIndex].GetTerrainKind();
    refundAmount = g_adwEngineerRailBuildCostByTerrainType[terrainKind];
    g_pGlobalMapState->ApplyEngineerRailCostDeltaForConnectedTiles(
        targetTileIndex, subtypeOrTargetProvince, pCivilianOrderEntry->ownerNationSlot);
    break;
  }
  case kUnitOrderBuildDepot:
    refundAmount = 2000;
    break;
  case kUnitOrderBuildPort:
    refundAmount = 3000;
    break;
  case kUnitOrderDevelopResource: {
    bool useHighNibble = ((subtypeOrTargetProvince == 0) || (subtypeOrTargetProvince == 8)) ? 1 : 0;
    unsigned char costClass =
        g_pGlobalMapState->GetDevelopmentLevel(targetTileIndex, useHighNibble);
    refundAmount = g_adwCivilianWorkOrderCostByClass[costClass];
    break;
  }
  case kUnitOrderBuildFort: {
    short cityIndex = g_pGlobalMapState->terrainStateTable[targetTileIndex].cityRecordIndex;
    signed char fortLevel = g_pGlobalMapState->cityScoreTable[cityIndex].fortLevel;
    refundAmount = g_awEngineerFortBuildCostByLevel[fortLevel];
    break;
  }
  case kUnitOrderPurchaseLand:
    refundAmount = g_pGlobalMapState->LandPrice(targetTileIndex);
    break;
  }

  ownerNationState->treasuryValue += refundAmount;
  g_pUiAnimator->FreeAni(PointerAddressLong32(pCivilianOrderEntry));

  pCivilianOrderEntry->SetOrders(kUnitOrderIdle, subtypeOrTargetProvince);
  if ((subtypeOrTargetProvince != 0) && (subtypeOrTargetProvince != -1)) {
    MoveAndRedrawUnit(subtypeOrTargetProvince, pCivilianOrderEntry);
  }

  TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
  if (mapUberPicture != NULL) {
    mapUberPicture->SetMapInteractionMode(0);
  }
  g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();

  selectedEntry = pCivilianOrderEntry;
  SetDimming(pCivilianOrderEntry);
  if (pCivilianOrderEntry != NULL) {
    pCivilianOrderEntry->MoveTo(pCivilianOrderEntry->tileIndex);

    TMapUberPicture* invalidateTarget = g_pViewMgr->mapUberPicture;
    if (invalidateTarget != NULL) {
      invalidateTarget->InvalidateTile(pCivilianOrderEntry->tileIndex);
    }

    TMapUberPicture* refreshTarget = g_pViewMgr->mapUberPicture;
    if (refreshTarget != NULL) {
      static_cast<TCivToolbar*>(
          refreshTarget->categoryPages[refreshTarget->activeUnitCategoryIndex])
          ->SetSelectedUnit(pCivilianOrderEntry);
    }
  }

  if (mapUberPicture != NULL) {
    mapUberPicture->NoticeTile(pCivilianOrderEntry->tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x004d3310
bool TCivMgr::ImprovementClick(short nTileIndex) {
  TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetPlayerCountry()];
  int budget = activeNation->diplomacyBudgetBase / 10 + activeNation->treasuryValue;
  if (budget < 0) {
    budget = 0;
  }

  bool useHighNibble = (selectedEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner) ||
                        selectedEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitDriller))
                           ? 1
                           : 0;
  unsigned char costClass = g_pGlobalMapState->GetDevelopmentLevel(nTileIndex, useHighNibble);
  int cost = g_adwCivilianWorkOrderCostByClass[costClass];

  if (budget < cost) {
    CString costText;
    g_pSimMgr->NumToCurrency(cost, &costText);
    CString templateText;
    g_pSimMgr->GetString(0x2745, 8, &templateText);
    CString finalMessage;
    scanBracketExpressions(g_pSimMgr, &finalMessage, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(costText));
    g_pViewMgr->ModalMessage(finalMessage, g_ptCivilianOrderModalMessage, 2, 0);
    return false;
  }

  selectedEntry->SetOrders(kUnitOrderDevelopResource, selectedEntry->tileIndex);
  MoveAndRedrawUnit(nTileIndex, g_pSelectedCivilianOrderState->selectedEntry);

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

  selectedEntry->completionMarker = sfxCode;
  g_apNationStates[g_pSimMgr->GetPlayerCountry()]->AddToTreasury(-cost);
  g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();
  return true;
}

// FUNCTION: IMPERIALISM 0x004d3610
bool TCivMgr::PurchaseClick(short nTileIndex) {
  TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetPlayerCountry()];
  int availableCash = activeNation->diplomacyBudgetBase / 100 + activeNation->treasuryValue;
  if (availableCash < 0) {
    availableCash = 0;
  }
  int purchaseCost = g_pGlobalMapState->LandPrice(nTileIndex);

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
    // ORACLE: Mac Strings.rsrc: "the governor of [1] will sell us this land for [2]".
    g_pSimMgr->GetString(0x274d, 1, &templateText);
    scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(cityName), static_cast<LPCSTR>(costText));
    if (g_pViewMgr->ModalMessage(4, titleText, formattedText, g_ptCivilianOrderModalMessage, 0,
                                 1)) {
      selectedEntry->SetOrders(kUnitOrderPurchaseLand, selectedEntry->tileIndex);
      MoveAndRedrawUnit(nTileIndex, g_pSelectedCivilianOrderState->selectedEntry);
      g_pSfxPlaybackSystem->PlaySoundEffect(0x2335, 0, 1);
      g_apNationStates[g_pSimMgr->GetPlayerCountry()]->AddToTreasury(-purchaseCost);
      g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();

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
    // ORACLE: Mac Strings.rsrc: "the governor of [1] has set the price ... we cannot afford".
    g_pSimMgr->GetString(0x274d, 2, &templateText);
    scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(cityName), static_cast<LPCSTR>(costText));
    g_pViewMgr->ModalMessage(3, titleText, formattedText, g_ptCivilianOrderModalMessage, 0, 0);
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004d39d0
bool TCivMgr::ProspectorClick(short nTileIndex) {
  selectedEntry->SetOrders(static_cast<UnitOrder>(8), selectedEntry->tileIndex);
  MoveAndRedrawUnit(nTileIndex, selectedEntry);
  g_pSfxPlaybackSystem->PlaySoundEffect(0x232e, 0, 1);
  unsigned int startTick = GetTickCountDiv16();
  unsigned int nowTick;
  do {
    PumpUiMessagesAndBackgroundTasks(1);
    nowTick = GetTickCountDiv16();
    if (nowTick < startTick) {
      return true;
    }
  } while (nowTick - startTick < 0x1e);
  return true;
}

// FUNCTION: IMPERIALISM 0x004d3a60
bool TCivMgr::EngineerClick(short nTileIndex) {
  TCivUnit* pCiv = selectedEntry;
  if (pCiv == NULL) {
    return false;
  }

  bool actionFinalized = false;
  bool refreshPanel = false;

  if (nTileIndex == pCiv->tileIndex) {
    int choice = g_pViewMgr->MakeEngineeringDialog();
    if (choice == kControlTagFort) { // 'fort'
      short cityIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
      int fortLevel = g_pGlobalMapState->cityScoreTable[cityIndex].fortLevel;
      short cost = g_awEngineerFortBuildCostByLevel[fortLevel];

      short nationId = g_pSimMgr->GetPlayerCountry();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < cost) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pSimMgr->NumToCurrency(cost, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pViewMgr->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetPlayerCountry();
        g_apNationStates[nationId]->treasuryValue -= cost;
        pCiv->SetOrders(kUnitOrderBuildDepot, pCiv->tileIndex);
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232c, 0, 1);
        actionFinalized = true;
      }
    } else if (choice == kControlTagPort) { // 'port'
      short nationId = g_pSimMgr->GetPlayerCountry();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < 3000) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pSimMgr->NumToCurrency(3000, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pViewMgr->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetPlayerCountry();
        g_apNationStates[nationId]->treasuryValue -= 3000;
        pCiv->SetOrders(kUnitOrderBuildPort, pCiv->tileIndex);
        if (g_pViewMgr->mapUberPicture != NULL) {
          g_pViewMgr->mapUberPicture->InvalidateTile(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232b, 0, 1);
        actionFinalized = true;
      }
    } else if (choice == kSummaryTagRail) { // 'rail'
      short nationId = g_pSimMgr->GetPlayerCountry();
      int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
                 g_apNationStates[nationId]->treasuryValue;
      int availableCash = (cash < 0) ? 0 : cash;

      if (availableCash < 2000) {
        CString pszFormattedText;
        CString pszTemplateText;
        CString costString;

        g_pSimMgr->NumToCurrency(2000, &costString);
        g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
        scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                               static_cast<LPCSTR>(costString));

        g_pViewMgr->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
      } else {
        short nationId = g_pSimMgr->GetPlayerCountry();
        g_apNationStates[nationId]->treasuryValue -= 2000;
        pCiv->SetOrders(kUnitOrderBuildFort, pCiv->tileIndex);
        if (g_pViewMgr->mapUberPicture != NULL) {
          g_pViewMgr->mapUberPicture->InvalidateTile(nTileIndex);
        }
        g_pSfxPlaybackSystem->PlaySoundEffect(0x232a, 0, 1);
        actionFinalized = true;
      }
    }
  } else { // adjacent tile click
    StrategicTerrainKind terrainKind =
        g_pGlobalMapState->terrainStateTable[nTileIndex].GetTerrainKind();
    int cost = g_adwEngineerRailBuildCostByTerrainType[terrainKind];

    short nationId = g_pSimMgr->GetPlayerCountry();
    int cash = g_apNationStates[nationId]->diplomacyBudgetBase / 100 +
               g_apNationStates[nationId]->treasuryValue;
    int availableCash = (cash < 0) ? 0 : cash;

    if (availableCash < cost) {
      CString pszFormattedText;
      CString pszTemplateText;
      CString costString;

      g_pSimMgr->NumToCurrency(cost, &costString);
      g_pSimMgr->GetString(0x2745, 8, &pszTemplateText);
      scanBracketExpressions(g_pSimMgr, &pszFormattedText, static_cast<LPCSTR>(pszTemplateText),
                             static_cast<LPCSTR>(costString));

      g_pViewMgr->ModalMessage(pszFormattedText, g_ptCivilianOrderModalMessage, 2, 0);
    } else {
      short nationId = g_pSimMgr->GetPlayerCountry();
      g_apNationStates[nationId]->treasuryValue -= cost;
      g_pGlobalMapState->AddRailSegment(pCiv->tileIndex, nTileIndex, pCiv->ownerNationSlot);
      pCiv->SetOrders(kUnitOrderLayRail, pCiv->tileIndex);
      g_pSfxPlaybackSystem->PlaySoundEffect(0x2329, 0, 1);
      actionFinalized = true;
      refreshPanel = true;
    }
  }

  if (actionFinalized) {
    MoveAndRedrawUnit(nTileIndex, pCiv);

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
    g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();
  }

  return actionFinalized;
}

// FUNCTION: IMPERIALISM 0x004d4310
void TCivMgr::MoveAndRedrawUnit(short nNewTileIndex, TCivUnit* pCivOrderEntry) {
  short previousTile = pCivOrderEntry->tileIndex;
  pCivOrderEntry->MoveTo(nNewTileIndex);
  if (previousTile != -1 && g_pViewMgr->mapUberPicture != NULL) {
    g_pViewMgr->mapUberPicture->RedrawTile(previousTile);
  }
  if (nNewTileIndex != -1 && g_pViewMgr->mapUberPicture != NULL) {
    g_pViewMgr->mapUberPicture->RedrawTile(nNewTileIndex);
  }
}
// FUNCTION: IMPERIALISM 0x004d4390
void TCivMgr::CompletedOrders(TCivUnit* order) {
  switch (order->unitOrder - kUnitOrderLayRail) {
  case 5: {
    bool selectHighNibble = order->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner) ||
                            order->orderType == EncodeCivilianUnitKind(kCivilianUnitDriller);
    byte result = g_pGlobalMapState->GetDevelopmentLevel(order->tileIndex, selectHighNibble);
    g_pGlobalMapState->SetDevelopmentLevel(order->tileIndex, selectHighNibble,
                                           static_cast<byte>(result + 1), true);
    break;
  }
  case 8:
    g_pGlobalMapState->terrainStateTable[order->tileIndex].secondaryOwnerNationTag =
        static_cast<signed char>(order->ownerNationSlot);
    break;
  case 3: {
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[order->tileIndex];
    tile.pendingDevelopmentFlag |= static_cast<unsigned char>(1 << order->ownerNationSlot);
    if (g_apNationStates[order->ownerNationSlot]->diplomacyEligibility != 0 &&
        g_pGlobalMapState->AreMineralsPresent(order->tileIndex) != 0) {
      order->completionMarker = 0x232f;
    }
    break;
  }
  case 1:
    g_pGlobalMapState->BuildRailhead(order->tileIndex, order->ownerNationSlot);
    g_apNationStates[order->ownerNationSlot]->TraceSupplyRoutes(NULL);
    order->completionMarker = 0x232a;
    break;
  case 2:
    g_pGlobalMapState->BuildPort(order->tileIndex, order->ownerNationSlot);
    g_apNationStates[order->ownerNationSlot]->TraceSupplyRoutes(NULL);
    order->completionMarker = 0x232b;
    break;
  case 0:
    g_pGlobalMapState->SetHexAdjacencyDirectionFlagsForTilePair(
        order->orderTargetIndex, order->tileIndex, order->ownerNationSlot);
    order->completionMarker = 0x2329;
    break;
  case 7:
    g_pGlobalMapState->BuildFort(
        g_pGlobalMapState->terrainStateTable[order->tileIndex].cityRecordIndex);
    break;
  default:
    break;
  }

  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleStandalone) {
    return;
  }

  switch (order->unitOrder - kUnitOrderLayRail) {
  case 0:
    SendTileNews(order->orderTargetIndex);
  case 3:
  case 5:
  case 8:
    SendTileNews(order->tileIndex);
    return;
  case 1:
  case 2: {
    short neighborBuf[7];
    TMapMgr::GetNeighborTileIDArray(order->tileIndex, neighborBuf,
                                    g_pGlobalMapState->hexNeighborWrapHorizontally);
    neighborBuf[6] = order->tileIndex;
    TTerrainStateRecord& centerTile = g_pGlobalMapState->terrainStateTable[order->tileIndex];
    for (int i = 0; i < 7; ++i) {
      short t = neighborBuf[i];
      if (t == -1) {
        continue;
      }
      SendTileNews(t);
      short cityIdx = g_pGlobalMapState->terrainStateTable[t].cityRecordIndex;
      if ((centerTile.activeFlags & 3) != 0 && centerTile.gateFlag != 0 && cityIdx != -1) {
        g_pGameFlowState->DispatchCityRedrawInvalidateEvent(cityIdx);
      }
    }
    return;
  }
  case 7: {
    short cityIdx = g_pGlobalMapState->terrainStateTable[order->tileIndex].cityRecordIndex;
    g_pGameFlowState->DispatchCityRedrawInvalidateEvent(cityIdx);
    SendTileNews(g_pGlobalMapState->cityScoreTable[cityIdx].cityTileIndex);
    return;
  }
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004d4740
void TCivMgr::ResolveCivilianDisputes() {
  for (int tileIndex = 0; tileIndex < kStrategicTileCount; ++tileIndex) {
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    TCivUnit* order = tile.firstCivilianOrder;
    if (order == 0 || order->nextAtLocation == 0) {
      continue;
    }

    TCivUnit* competingOrders[7] = {0};
    int competingCount = 0;
    while (order != 0) {
      if (order->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper) &&
          order->unitOrder == kUnitOrderPurchaseLand) {
        competingOrders[competingCount++] = order;
      }
      order = static_cast<TCivUnit*>(order->nextAtLocation);
    }
    if (competingCount <= 1) {
      continue;
    }

    int ownerNationSlot = tile.ownerNationTag;
    TCivUnit* winningOrder = competingOrders[0];
    short winningStanding =
        g_pDiplomacyTurnStateManager
            ->relationStandingScores[winningOrder->ownerNationSlot * kNationSlotCount +
                                     ownerNationSlot];
    for (int candidateIndex = 1; candidateIndex < competingCount; ++candidateIndex) {
      TCivUnit* candidate = competingOrders[candidateIndex];
      short candidateStanding =
          g_pDiplomacyTurnStateManager
              ->relationStandingScores[candidate->ownerNationSlot * kNationSlotCount +
                                       ownerNationSlot];
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

      short losingNationSlot = losingOrder->ownerNationSlot;
      losingOrder->SetOrders(kUnitOrderIdle, -1);
      g_apNationStates[losingNationSlot]->treasuryValue +=
          g_pGlobalMapState->LandPrice(static_cast<short>(tileIndex));

      if (g_apNationStates[losingNationSlot]->diplomacyEligibility != 0) {
        TLandSaleEvent* event = new TLandSaleEvent();
        event->ILandSaleEvent(static_cast<short>(tileIndex), winningOrder->ownerNationSlot);
        g_apNationStates[losingNationSlot]->AddTurnStartEvent(event);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004d49f0
void TCivMgr::WakeAll(int nationId) {
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

  TMapUberPicture* mapView = g_pViewMgr->mapUberPicture;
  if (mapView != 0 && !mapView->IsAUnitSelected()) {
    mapView->CycleMapInteractionSelectionAfterHandledClick();
  }
}
