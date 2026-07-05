#include "game/TArmyMgr.h"

#include "game/CIterator.h"
#include "game/CString.h"
#include "game/TArmyStack.h"
#include "game/TCountry.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/TSortedList.h"
#include "game/TSoundPlayer.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h" // g_pSimMgr, g_pGlobalMapState, g_apTerrainTypeDescriptorTable, g_pSfxPlaybackSystem, g_apNationStates, g_pUiRuntimeContext
#include "game/mapped_flavor_text.h" // scanBracketExpressions
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004a1810
// TArmyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a1850
// TArmyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyMgr, TObject)

extern undefined4 GenerateThreadLocalRandom15(void);

TArmyMgr::TArmyMgr() {}

// SYNTHETIC: IMPERIALISM 0x004a18a0
// TArmyMgr::`scalar deleting destructor'
TArmyMgr::~TArmyMgr() {}

// FUNCTION: IMPERIALISM 0x004a1a00
void TArmyMgr::Free() {}

// FUNCTION: IMPERIALISM 0x004a1b80
void TArmyMgr::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a1dd0
void TArmyMgr::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a1e40
undefined TArmyMgr::OrphanCallChain_C4_I26_004a1e40() {
  // g_pSimMgr's preferenceValues[0] is reused as a dual-purpose int slot (matching the
  // established pattern in TMultiplayerMgr.cpp); == 2 selects the alternate branch here.
  if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2) {
    this->IterateLinkedListCursorAndClearPerTileByte0F();
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
  } else {
    this->ProcessTileUnitListsAndApplyRandomStatusUpdates();
    this->pendingRebuildFlag10 = 1;
    this->ProcessPendingArmyStacksForBattleOrRelocation();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a1eb0
void TArmyMgr::ReleaseThreeLinkedObjectsAndResetTerrainDescriptorFlags() {
  if (this->cachedObject39c != nullptr) {
    this->cachedObject39c->Free();
  }
  this->cachedObject39c = nullptr;
  if (this->cachedObject3a0 != nullptr) {
    this->cachedObject3a0->Free();
  }
  this->cachedObject3a0 = nullptr;
  if (this->cachedObject3a4 != nullptr) {
    this->cachedObject3a4->Free();
  }
  this->cachedObject3a4 = nullptr;

  this->IterateLinkedListCursorAndClearPerTileByte0F();
  this->WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0();

  if (this->needsTerrainRefreshFlag39a != 0) {
    g_pStrategicMapViewSystem->RebuildNationClipRegionsAndDispatchMapEvent();
    for (int i = 0; i < kTerrainTypeDescriptorTableCount; ++i) {
      if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
        g_apTerrainTypeDescriptorTable[i]->SetSerializedField8c(-1);
      }
    }
  }
  this->needsTerrainRefreshFlag39a = 0;
  g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
}

// FUNCTION: IMPERIALISM 0x004a1f80
undefined TArmyMgr::ProcessTileUnitListsAndApplyRandomStatusUpdates() {
  TArmyStack* stack = nullptr;
  for (int tileIndex = 0; tileIndex < 0x180; ++tileIndex) {
    TUnit* unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
    short prevFieldC = -1;
    short prevField18 = -1;
    for (; unit != nullptr; unit = unit->nextOnTile) {
      short unitFieldC = unit->field_C;
      short unitField18 = unit->field_18;
      if (unitFieldC == -1) {
        TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
        if (milUnit->field_34 < 0x191) {
          milUnit->field_34 += 100;
        } else {
          milUnit->field_34 = 500;
        }
        if (unitField18 < 7 && g_apNationStates[unitField18]->diplomacyEligibilityA0 == 0) {
          unit->SetOrderModeSlot34(2, -1);
        }
        continue;
      }

      if (unitFieldC != prevFieldC || unitField18 != prevField18 || stack == nullptr) {
        bool foundExisting = false;
        int count = this->pendingUnitPool0c->GetCountSlot48();
        if (count != 0) {
          int index = 1;
          count = this->pendingUnitPool0c->GetCountSlot48();
          if (index <= count) {
            do {
              if (foundExisting) {
                break;
              }
              stack =
                  static_cast<TArmyStack*>(this->pendingUnitPool0c->GetEntryByOrdinalSlot4C(index));
              stack->AssertValid();
              if (stack->ownerNationCodeE == unitFieldC &&
                  static_cast<short>(static_cast<signed char>(stack->categoryFlag8)) ==
                      unitField18) {
                foundExisting = true;
              } else {
                ++index;
              }
              count = this->pendingUnitPool0c->GetCountSlot48();
            } while (index <= count);
          }
        }
        if (!foundExisting) {
          stack = new TArmyStack();
          stack->head14 = nullptr;
          stack->cursor18 = nullptr;
          stack->fieldA = 0;
          stack->field6 = 0;
          stack->field4 = 0;
          stack->categoryFlag8 = static_cast<unsigned char>(unitField18);
          stack->fieldC = 0;
          stack->ownerNationCodeE = unitFieldC;
          stack->tileIndex10 = static_cast<short>(tileIndex);
          this->pendingUnitPool0c->listState.AddHead(stack);
        }
        prevFieldC = unitFieldC;
        prevField18 = unitField18;
        if (stack == nullptr) {
          MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0x333);
        }
      }

      TArmyStackUnitNode* node = new TArmyStackUnitNode();
      if (node == nullptr) {
        MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
        TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xbeb);
      }
      node->unit = unit;
      node->next = stack->head14;
      ++stack->fieldA;
      stack->head14 = node;
    }
  }

  CIterator stackIter(this->pendingUnitPool0c);
  for (TArmyStack* item = static_cast<TArmyStack*>(stackIter.Reset()); stackIter.More();
       item = static_cast<TArmyStack*>(stackIter.Advance())) {
    item->cursor18 = item->head14;
    TArmyStackUnitNode* node = item->cursor18;
    TUnit* unit = (node != nullptr) ? node->unit : nullptr;
    short minClass = 3;
    short maxClass = 1;
    while (unit != nullptr) {
      short unitClass = g_awUnitCombatClassBySlot[unit->orderType];
      if (unitClass < minClass) {
        minClass = unitClass;
      }
      if (unitClass > maxClass) {
        maxClass = unitClass;
      }
      node = item->cursor18;
      if (node != nullptr) {
        node = node->next;
        item->cursor18 = node;
        unit = (node != nullptr) ? node->unit : nullptr;
      } else {
        unit = nullptr;
      }
    }
    item->field4 = g_abStackCompositionClassTable[minClass + maxClass * 4];
    int roll = GenerateThreadLocalRandom15();
    item->field6 = static_cast<short>((item->field4 << 8) + (roll & 0xff));
  }

  this->pendingUnitPool0c->VirtualSlot64();
  for (int i = 0; i < 0x180; ++i) {
    this->perTileOwnerNationCodeCache1c[i] =
        g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(i);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a2390
undefined TArmyMgr::ProcessPendingArmyStacksForBattleOrRelocation() {
  bool battleViewCreated = false;
  if (this->cachedObject39c != nullptr) {
    this->cachedObject39c->Free();
  }
  this->cachedObject39c = nullptr;
  if (this->cachedObject3a0 != nullptr) {
    this->cachedObject3a0->Free();
  }
  this->cachedObject3a0 = nullptr;
  if (this->cachedObject3a4 != nullptr) {
    this->cachedObject3a4->Free();
  }
  this->cachedObject3a4 = nullptr;

  int stackCount = this->pendingUnitPool0c->GetCountSlot48();
  if (this->pendingRebuildFlag10 <= stackCount) {
    do {
      int cursor = this->pendingRebuildFlag10;
      stackCount = this->pendingUnitPool0c->GetCountSlot48();
      if (stackCount < cursor) {
        break;
      }
      this->pendingRebuildFlag10 = cursor + 1;
      TArmyStack* stack =
          static_cast<TArmyStack*>(this->pendingUnitPool0c->GetEntryByOrdinalSlot4C(cursor));
      stack->AssertValid();
      if (this->perTileOwnerNationCodeCache1c[stack->ownerNationCodeE] ==
          static_cast<short>(static_cast<signed char>(stack->categoryFlag8))) {
        stack->cursor18 = stack->head14;
        TArmyStackUnitNode* node = stack->cursor18;
        TUnit* unit = (node != nullptr) ? node->unit : nullptr;
        while (unit != nullptr) {
          unit->VTableSlot10(unit->field_C);
          unit->SetOrderModeSlot34(0, -1);
          node = stack->cursor18;
          if (node != nullptr) {
            node = node->next;
            stack->cursor18 = node;
            unit = (node != nullptr) ? node->unit : nullptr;
          } else {
            unit = nullptr;
          }
        }
      } else {
        battleViewCreated =
            this->TryCreateTacticalBattleViewForTileArmies(stack, stack->ownerNationCodeE) != 0;
      }
    } while (!battleViewCreated);
    stackCount = this->pendingUnitPool0c->GetCountSlot48();
    if (this->pendingRebuildFlag10 <= stackCount) {
      return 0;
    }
    if (battleViewCreated) {
      return 0;
    }
  }
  this->ReleaseThreeLinkedObjectsAndResetTerrainDescriptorFlags();
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a2500
undefined TArmyMgr::IterateLinkedListCursorAndClearPerTileByte0F() {
  this->pendingUnitPool0c->FreePayloadsSlot54();
  g_pGlobalMapState->ClearPerTileByte0FForAllMapTiles();

  for (int i = 0; i < kTerrainTypeDescriptorTableCount; ++i) {
    TCountry* nation = g_apTerrainTypeDescriptorTable[i];
    if (nation == nullptr) {
      continue;
    }
    TSortedList* unitList = nation->militaryUnitList44;
    if (unitList == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0x39b);
    }

    CIterator unitIter(unitList);
    for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
      if (unit->field_34 > 0 && unit->field_6 != -1) {
        unit->DispatchSlot2C();
      } else {
        unit->DetachUnitOrderFromOwnerAndReset();
        unit->Free();
      }
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a3200
undefined TArmyMgr::TryCreateTacticalBattleViewForTileArmies(TArmyStack* stack,
                                                             short ownerNationCode) {
  (void)stack;
  (void)ownerNationCode;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a35e0
undefined TArmyMgr::RedistributeUnitOrderQueueToRandomAdjacentRegion(TArmyStack* stack,
                                                                     short tileIndex) {
  stack->cursor18 = stack->head14;
  TUnit* headUnit = (stack->head14 != nullptr) ? stack->head14->unit : nullptr;
  short headUnitTag = headUnit->field_18;

  const TGlobalMapCityScoreRecord& record = g_pGlobalMapState->cityScoreTable[tileIndex];
  short candidateRegions[12];
  int candidateCount = 0;
  for (int i = 0; i < 0x18; ++i) {
    short regionId = record.adjacentRegionIds0A[i];
    if (regionId == -1) {
      break;
    }
    if (this->perTileOwnerNationCodeCache1c[regionId] == headUnitTag) {
      candidateRegions[candidateCount] = regionId;
      ++candidateCount;
    }
  }

  if (candidateCount == 0) {
    stack->cursor18 = stack->head14;
    TArmyStackUnitNode* node = stack->cursor18;
    TUnit* unit = (node != nullptr) ? node->unit : nullptr;
    while (unit != nullptr) {
      if (static_cast<TMilitaryUnit*>(unit)->field_34 != 0) {
        unit->DetachUnitOrderFromOwnerAndReset();
      }
      node = stack->cursor18;
      if (node != nullptr) {
        node = node->next;
        stack->cursor18 = node;
        unit = (node != nullptr) ? node->unit : nullptr;
      } else {
        unit = nullptr;
      }
    }
    return 0;
  }

  short chosenRegion = candidateRegions[GenerateThreadLocalRandom15() % candidateCount];
  stack->cursor18 = stack->head14;
  TArmyStackUnitNode* node = stack->cursor18;
  TUnit* unit = (node != nullptr) ? node->unit : nullptr;
  while (unit != nullptr) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->orderType] == 0) {
      unit->DetachUnitOrderFromOwnerAndReset();
    } else {
      unit->SetOrderModeSlot34(1, chosenRegion);
    }
    node = stack->cursor18;
    if (node != nullptr) {
      node = node->next;
      stack->cursor18 = node;
      unit = (node != nullptr) ? node->unit : nullptr;
    } else {
      unit = nullptr;
    }
  }

  stack->cursor18 = stack->head14;
  node = stack->cursor18;
  unit = (node != nullptr) ? node->unit : nullptr;
  if (unit == nullptr) {
    return 0;
  }
  do {
    unit->VTableSlot10(unit->field_C);
    unit->SetOrderModeSlot34(0, -1);
    node = stack->cursor18;
    if (node != nullptr) {
      node = node->next;
      stack->cursor18 = node;
      unit = (node != nullptr) ? node->unit : nullptr;
    } else {
      unit = nullptr;
    }
  } while (unit != nullptr);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a37b0
undefined TArmyMgr::ResetAndRelocateUnitOrderQueue_004a37b0(TArmyStack* stack) {
  stack->cursor18 = stack->head14;
  TArmyStackUnitNode* node = stack->cursor18;
  TUnit* unit = (node != nullptr) ? node->unit : nullptr;
  while (unit != nullptr) {
    unit->SetOrderModeSlot34(0, -1);
    if (unit->field_6 != stack->tileIndex10) {
      unit->VTableSlot10(stack->tileIndex10);
    }
    node = stack->cursor18;
    if (node != nullptr) {
      node = node->next;
      stack->cursor18 = node;
      unit = (node != nullptr) ? node->unit : nullptr;
    } else {
      unit = nullptr;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a3830
undefined TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a3bc0
undefined TArmyMgr::WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a3d90
undefined TArmyMgr::DispatchTileActionByKind_004a3d90(int contextArg, short actionKind) {
  if (actionKind == 1 || actionKind == 4) {
    this->SelectMovableUnitOnCurrentTileAndPlaySfx(contextArg);
  } else if (actionKind == 7) {
    this->CommitCityActionGateCostIfAffordable(contextArg);
  }

  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
    if (unit->field_8 == 4) {
      unit->SetOrderModeSlot34(0, -1);
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a3e50
bool TArmyMgr::SelectMovableUnitOnCurrentTileAndPlaySfx(int contextArg) {
  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  bool foundMovableUnit = false;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
    if (unit->field_8 == 0 && unit->GetUnitMovementClassId() != 0) {
      unit->SetOrderModeSlot34(1, contextArg);
      foundMovableUnit = true;
    }
  }
  if (foundMovableUnit) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aa7, 0, 1);
    g_pGlobalMapState->MarkAdjacentHexOrderDirectionAndSelectTile(this->pendingMapActionIndex,
                                                                  contextArg, 0);
  }
  return foundMovableUnit;
}

// FUNCTION: IMPERIALISM 0x004a3f30
bool TArmyMgr::CommitCityActionGateCostIfAffordable(int contextArg) {
  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  int totalCost = 0;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
    if (unit->field_8 == 0 && unit->GetUnitMovementClassId() != 0) {
      totalCost += unit->GetUnitTypeCostPoints();
    }
  }

  short nationSlot = g_pSimMgr->GetActiveNationId();
  if (totalCost == 0) {
    return false;
  }

  TGreatPower* nation = g_apNationStates[nationSlot];
  if (totalCost <= nation->field900) {
    this->SelectMovableUnitOnCurrentTileAndPlaySfx(contextArg);
    nation->field900 -= totalCost;
    return true;
  }

  // Insufficient funds: compose and dispatch a localized message with the current
  // budget and the required cost (ground truth builds both via a direct
  // CString::Format("%d", ...) rather than TSimMgr::FormatIntegerString).
  CString currentAmountString;
  currentAmountString.Format("%d", nation->field900);
  CString costString;
  costString.Format("%d", totalCost);
  CString templateText;
  g_pSimMgr->GetString(0x2745, 0, &templateText);
  CString formattedMessage;
  scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(currentAmountString), static_cast<LPCSTR>(costString));
  reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
      ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &formattedMessage);
  return false;
}

// FUNCTION: IMPERIALISM 0x004a4260
undefined TArmyMgr::OrphanCallChain_C1_I34_004a4260(int mode) {
  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
    if (unit->field_8 == 0) {
      unit->SetOrderModeSlot34(mode, -1);
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a4870
undefined TArmyMgr::HandleMapClickByComputedCursorState() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a4ad0
undefined TArmyMgr::HandleMapClickByCivilianCursorState() {
  return 0;
}
