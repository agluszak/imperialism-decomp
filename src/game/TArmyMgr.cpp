#include "game/TArmyMgr.h"

#include "game/CIterator.h"
#include "game/CString.h"
#include "game/TArmyStack.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/TSortedList.h"
#include "game/TSoundPlayer.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h" // g_pSimMgr, g_pGlobalMapState, g_apTerrainTypeDescriptorTable, g_pSfxPlaybackSystem, g_apNationStates, g_pUiRuntimeContext
#include "game/mapped_flavor_text.h" // scanBracketExpressions
#include "game/nation_slot_eligibility.h" // IsNationSlotEligibleForEventProcessing
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004a1810
// TArmyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a1850
// TArmyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyMgr, TObject)

extern undefined4 GenerateThreadLocalRandom15(void);

// Own-source function (not a TArmyMgr method -- ground truth doesn't touch `this`).
// Classifies a map-click as: 6 (already visited this pass), 0 (blocked -- dialog/order
// context active, or tile already has a pending civilian order), 8 (blocked -- active
// nation not eligible, or a diplomacy-target mismatch with the tile's owner), or 2
// (click accepted). Defined below (0x4a4960) in address order; forward-declared here
// for HandleMapClickByComputedCursorState's use.
static int __stdcall ComputeMapCursorStateIndex(short tileIndex, short mode);

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

// Own-source function (not a TArmyMgr method -- neither callsite reliably sets ECX to
// `this` before calling it, and it cleans its own stack args, i.e. plain __cdecl).
// Builds/dispatches the army-context action records for the "our stack" / "enemy stack"
// pairing computed by TryCreateTacticalBattleViewForTileArmies; mode distinguishes the
// peaceful (0) vs. no-enemy (1) paths.
// FUNCTION: IMPERIALISM 0x004a2900
static void BuildArmyContextActionRecordsAndDispatchLabel(TArmyStack* ourStack,
                                                          TArmyStack* enemyStack, int mode,
                                                          int ownerNationCodeInt, int unused) {
  // TODO: port body @ 0x4a2900 (1791 bytes; large, not yet ported).
  (void)ourStack;
  (void)enemyStack;
  (void)mode;
  (void)ownerNationCodeInt;
  (void)unused;
}

// FUNCTION: IMPERIALISM 0x004a3200
bool TArmyMgr::TryCreateTacticalBattleViewForTileArmies(TArmyStack* stack, short ownerNationCode) {
  bool tacticalViewCreated = false;
  TArmyStackUnitNode* headNode = stack->head14;
  stack->cursor18 = headNode;
  TUnit* curUnit = (headNode != nullptr) ? headNode->unit : nullptr;

  // Partition stack's own unit chain into a new "our stack" containing only the units
  // whose field_C (order-owner nation) matches ownerNationCode; stack->head14 itself is
  // left untouched, only its cursor18 iteration state advances.
  TArmyStack* ourStack = new TArmyStack();
  ourStack->head14 = nullptr;
  ourStack->cursor18 = nullptr;
  ourStack->categoryFlag8 = static_cast<unsigned char>(curUnit->field_18);
  ourStack->fieldA = 0;
  ourStack->field6 = 0;
  ourStack->field4 = 0;
  ourStack->fieldC = 0;
  ourStack->ownerNationCodeE = ownerNationCode;
  ourStack->tileIndex10 = curUnit->field_6;

  while (curUnit != nullptr) {
    if (curUnit->field_C == ownerNationCode) {
      TArmyStackUnitNode* node = new TArmyStackUnitNode();
      if (node == nullptr) {
        MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
        TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xbeb);
      }
      node->unit = curUnit;
      node->next = ourStack->head14;
      ++ourStack->fieldA;
      ourStack->head14 = node;
    }
    TArmyStackUnitNode* nextNode = stack->cursor18;
    if (nextNode == nullptr) {
      curUnit = nullptr;
    } else {
      nextNode = nextNode->next;
      stack->cursor18 = nextNode;
      curUnit = (nextNode != nullptr) ? nextNode->unit : nullptr;
    }
  }

  TArmyStack* enemyStack = nullptr;
  if (ourStack->fieldA != 0) {
    int ownerNationCodeInt = ownerNationCode;
    short cachedOwnerAtTile = this->perTileOwnerNationCodeCache1c[ownerNationCodeInt];

    // The "enemy stack" is every unit currently garrisoned at the region/slot identified
    // by ownerNationCode -- ground truth indexes cityScoreTable directly by this value
    // rather than by a separately-resolved tile index.
    enemyStack = new TArmyStack();
    enemyStack->head14 = nullptr;
    enemyStack->cursor18 = nullptr;
    enemyStack->categoryFlag8 = static_cast<unsigned char>(cachedOwnerAtTile);
    enemyStack->fieldA = 0;
    enemyStack->field6 = 0;
    enemyStack->field4 = 0;
    enemyStack->fieldC = 0;
    enemyStack->ownerNationCodeE = ownerNationCode;
    enemyStack->tileIndex10 = ownerNationCode;

    TMilitaryUnit* enemyUnit = nullptr;
    if (ownerNationCode >= 0 && ownerNationCode < 0x180) {
      enemyUnit = g_pGlobalMapState->cityScoreTable[ownerNationCodeInt].stationedUnitChain98;
    }
    for (; enemyUnit != nullptr; enemyUnit = static_cast<TMilitaryUnit*>(enemyUnit->nextOnTile)) {
      TArmyStackUnitNode* node = new TArmyStackUnitNode();
      if (node == nullptr) {
        MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
        TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xbeb);
      }
      node->unit = enemyUnit;
      node->next = enemyStack->head14;
      ++enemyStack->fieldA;
      enemyStack->head14 = node;
    }

    if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
            ourStack->categoryFlag8, cachedOwnerAtTile) == 0) {
      // Relation is current: no battle -- dispatch the peaceful army-context path and
      // relocate our own stack instead.
      BuildArmyContextActionRecordsAndDispatchLabel(ourStack, enemyStack, 0, ownerNationCodeInt, 0);
      this->ResetAndRelocateUnitOrderQueue_004a37b0(ourStack);
    } else if (enemyStack->fieldA != 0) {
      // Ground truth also loops over g_apNationStates here (advancing a pointer with no
      // observable side effect -- the result is never read); not reproduced.
      tacticalViewCreated = true;
      this->CreateTacticalBattleViewAndInitializeBattleSetup(ourStack, enemyStack,
                                                             ownerNationCodeInt);
    } else {
      // No enemy units present: dispatch the army-context path (mode 1), relocate/reset
      // our own stack's units in place, then update the per-tile owner cache to reflect
      // our stack taking over.
      BuildArmyContextActionRecordsAndDispatchLabel(ourStack, enemyStack, 1, ownerNationCodeInt, 0);
      ourStack->cursor18 = ourStack->head14;
      TArmyStackUnitNode* node = ourStack->cursor18;
      TUnit* unit = (node != nullptr) ? node->unit : nullptr;
      while (unit != nullptr) {
        unit->VTableSlot10(unit->field_C);
        unit->SetOrderModeSlot34(0, -1);
        node = ourStack->cursor18;
        if (node != nullptr) {
          node = node->next;
          ourStack->cursor18 = node;
          unit = (node != nullptr) ? node->unit : nullptr;
        } else {
          unit = nullptr;
        }
      }
      this->perTileOwnerNationCodeCache1c[ownerNationCodeInt] = ourStack->categoryFlag8;
    }
  }

  if (!tacticalViewCreated) {
    if (ourStack != nullptr) {
      ourStack->Free();
    }
    if (enemyStack != nullptr) {
      enemyStack->Free();
    }
  }
  return tacticalViewCreated;
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

// Not ground truth's own function -- ground truth repeats this exact eligibility check
// inline 4 times inside UpdateDualLinkedEntryMetersAndBlinkState; factored out here rather
// than duplicated.
static bool IsUnitMeterEligible(TUnit* unit) {
  TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
  return milUnit->field_34 > milUnit->field_3C / 2 && (milUnit->field_3A & 2) == 0;
}

// FUNCTION: IMPERIALISM 0x004a3830
bool TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState(TArmyStack* stack1, TArmyStack* stack2) {
  // Phase 1: snapshot stack1's units' field_34 into field_3C and clear blink-mask bits 1/2,
  // stopping early the first time a unit's fort-level attacker-penalty lookup is 0.
  TUnit* unit = stack1->ResetCursorAndGetHeadUnit();
  while (unit != nullptr) {
    stack1->fortLevelAttackerPenaltyCache9 = static_cast<unsigned char>(
        g_anFortLevelAttackerPenaltyPercentByLevel[g_pGlobalMapState->cityScoreTable[unit->field_6]
                                                       .fortLevel03]);
    if (stack1->fortLevelAttackerPenaltyCache9 == 0) {
      break;
    }
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    milUnit->field_3C = milUnit->field_34;
    milUnit->SetOrClearWordMaskBits3a(1, false);
    milUnit->SetOrClearWordMaskBits3a(2, false);
    unit = stack1->AdvanceCursorAndGetUnit();
  }

  // Phase 2: same for stack2, except blink-mask bit 1 is set from the unit's
  // blink-eligibility flag rather than always cleared.
  unit = stack2->ResetCursorAndGetHeadUnit();
  while (unit != nullptr) {
    stack2->fortLevelAttackerPenaltyCache9 = static_cast<unsigned char>(
        g_anFortLevelAttackerPenaltyPercentByLevel[g_pGlobalMapState->cityScoreTable[unit->field_6]
                                                       .fortLevel03]);
    if (stack2->fortLevelAttackerPenaltyCache9 == 0) {
      break;
    }
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    milUnit->field_3C = milUnit->field_34;
    bool blinkFlag = g_abUnitTypeBlinkEligibilityFlag[unit->orderType] != 0;
    milUnit->SetOrClearWordMaskBits3a(1, blinkFlag);
    milUnit->SetOrClearWordMaskBits3a(2, false);
    unit = stack2->AdvanceCursorAndGetUnit();
  }

  // Phase 3: repeatedly find one eligible unit per stack (field_34 still above half its
  // Phase 1/2 snapshot, and blink-mask bit 2 clear) and accumulate/decay a shared meter
  // across both stacks, until either side runs dry.
  int counter = 0;
  while (true) {
    TUnit* eligible1 = stack1->ResetCursorAndGetHeadUnit();
    while (eligible1 != nullptr && !IsUnitMeterEligible(eligible1)) {
      eligible1 = stack1->AdvanceCursorAndGetUnit();
    }
    if (eligible1 == nullptr) {
      break;
    }
    TUnit* eligible2 = stack2->ResetCursorAndGetHeadUnit();
    while (eligible2 != nullptr && !IsUnitMeterEligible(eligible2)) {
      eligible2 = stack2->AdvanceCursorAndGetUnit();
    }
    if (eligible2 == nullptr) {
      break;
    }

    int sum1 = 0;
    int count1 = 0;
    int sum2 = 0;
    int count2 = 0;
    stack1->AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(&sum1, &count1, counter);
    stack2->AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(&sum2, &count2, counter);
    stack1->ApplyRandomizedMeterDecayToEligibleLinkedEntries(sum1, count1, counter);
    stack2->ApplyRandomizedMeterDecayToEligibleLinkedEntries(sum2, count2, counter);
    ++counter;
  }

  // Neither side found an eligible pairing this round: re-check stack1 alone. If it still
  // has an eligible unit, boost stack1's meters (and give stack2 a plain refresh);
  // otherwise refresh stack1 plainly and boost stack2's instead.
  TUnit* probe = stack1->ResetCursorAndGetHeadUnit();
  bool stack1StillEligible = false;
  while (probe != nullptr) {
    if (IsUnitMeterEligible(probe)) {
      stack1StillEligible = true;
      break;
    }
    probe = stack1->AdvanceCursorAndGetUnit();
  }
  if (stack1StillEligible) {
    stack1->ApplyMeterGrowthToEligibleUnits(true);
    stack2->ApplyMeterGrowthToEligibleUnits(false);
    return true;
  }
  stack1->ApplyMeterGrowthToEligibleUnits(false);
  stack2->ApplyMeterGrowthToEligibleUnits(true);
  return false;
}

// FUNCTION: IMPERIALISM 0x004a3bc0
undefined TArmyMgr::WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0() {
  for (int tileIndex = 0; tileIndex < 0x180; ++tileIndex) {
    short cachedOwner = this->perTileOwnerNationCodeCache1c[tileIndex];
    signed char currentOwner = g_pGlobalMapState->cityScoreTable[tileIndex].ownerNationCode00;
    if (currentOwner == -1 || cachedOwner == currentOwner) {
      continue;
    }
    if (g_apTerrainTypeDescriptorTable[currentOwner]->IsEncodedNationSlotMinus200Equal(
            cachedOwner) != 0) {
      continue;
    }

    bool proceed = true;
    if (cachedOwner < 7 && currentOwner > 6 &&
        g_apTerrainTypeDescriptorTable[currentOwner]->needLevelByNation[1] == -1) {
      bool eligible = IsNationSlotEligibleForEventProcessing(cachedOwner) != 0;
      bool blockedByPeerBand = g_apNationStates[cachedOwner] != nullptr &&
                               g_apNationStates[cachedOwner]->needLevelByNation[1] > 99 &&
                               g_apNationStates[cachedOwner]->needLevelByNation[1] < 200;
      if (!eligible || blockedByPeerBand) {
        proceed = false;
      }
    }
    if (!proceed) {
      continue;
    }

    signed char primaryOwner = g_pGlobalMapState->cityScoreTable[tileIndex].ownerNationCode00;
    signed char secondaryOwner = g_pGlobalMapState->cityScoreTable[tileIndex].byte01;
    if (g_apTerrainTypeDescriptorTable[primaryOwner]->GetHomeRegionCityRecordIndex() == tileIndex) {
      g_apTerrainTypeDescriptorTable[primaryOwner]->ApplyJoinEmpireModeForTargetNation(cachedOwner,
                                                                                       0);
    } else if (g_apTerrainTypeDescriptorTable[secondaryOwner] != nullptr &&
               g_apTerrainTypeDescriptorTable[secondaryOwner]->GetHomeRegionCityRecordIndex() ==
                   tileIndex) {
      g_apTerrainTypeDescriptorTable[secondaryOwner]
          ->SetNationTransferTargetCodeAndNotifyEligiblePeers(cachedOwner);
    }
    // Ground truth ORs in an extra undefined upper-16-bit register (uVar6, leftover from
    // whichever branch above ran) into this call's second argument; that garbage upper
    // half isn't semantically meaningful, so cachedOwner alone is passed here.
    g_pGlobalMapState->DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
        static_cast<short>(tileIndex), cachedOwner);
    this->needsTerrainRefreshFlag39a = 1;
  }
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

// FUNCTION: IMPERIALISM 0x004a45e0
void TArmyMgr::SetActiveProvinceSelection(short tileIndex) {
  this->pendingMapActionIndex = tileIndex;
  if (tileIndex != -1) {
    TMilitaryUnit* unit = nullptr;
    if (tileIndex >= 0 && tileIndex < 0x180) {
      unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
    }
    for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
      if ((unit->field_8 == 4 || unit->field_8 == 3) &&
          g_awTacticalUnitCategoryCodeBySlot[unit->orderType] != 0) {
        unit->SetOrderModeSlot34(0, -1);
      }
    }
    // TODO: ground truth also dispatches
    // g_pUiRuntimeContext->mapUberPictureF0->categoryPages[activeUnitCategoryIndex96]'s
    // slot-0x74 (NotifyActiveNationChanged-shaped) virtual here, passing tileIndex. The
    // categoryPages[] receiver class isn't recovered yet (TMapUberPicture.h Hard Rule 12
    // caveat), so this one dispatch is left undone rather than faked.
  }
  g_pUiRuntimeContext->mapUberPictureF0->RefreshAfterSelectionChange();
}

// FUNCTION: IMPERIALISM 0x004a4870
undefined TArmyMgr::HandleMapClickByComputedCursorState(short tileIndex, short mode) {
  bool handled = false;
  int cursorState = ComputeMapCursorStateIndex(tileIndex, mode);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  switch (cursorState) {
  case 2:
    if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
      g_pUiRuntimeContext->mapUberPictureF0->SetMapInteractionMode(1);
      this->SetActiveProvinceSelection(cityRecordIndex);
      handled = true;
    }
    break;
  case 6:
    this->SetActiveProvinceAndBuildDirectionalOrderOverlays(tileIndex);
    return 1;
  case 8:
    this->BuildMapHintOverlayTextAndDispatchUiMessages(cityRecordIndex);
    return 1;
  }
  return handled;
}

// FUNCTION: IMPERIALISM 0x004a4960
static int __stdcall ComputeMapCursorStateIndex(short tileIndex, short mode) {
  TTerrainStateRecordView* rec = &g_pGlobalMapState->terrainStateTable[tileIndex];
  if (rec->perTileVisitedFlag0f > 0) {
    return 6;
  }
  if (mode != 2) {
    if (g_pUiRuntimeContext->mapUberPictureF0->OrphanLeaf_NoCall_Ins23_00597a10() != 0) {
      return 0;
    }
    if (mode != 2 && rec->firstCivilianOrder20 != nullptr) {
      return 0;
    }
  }
  if (((rec->activeFlags1c >> 5) & 1) == 0) {
    return 0;
  }
  short ownerTag = rec->ownerNationTag04;
  short activeNationId = g_pSimMgr->GetActiveNationId();
  if (IsNationSlotEligibleForEventProcessing(activeNationId) == 0) {
    return 8;
  }
  activeNationId = g_pSimMgr->GetActiveNationId();
  if (ownerTag != activeNationId) {
    TCountry* owner = g_apTerrainTypeDescriptorTable[ownerTag];
    activeNationId = g_pSimMgr->GetActiveNationId();
    if (owner->IsEncodedNationSlotMinus200Equal(activeNationId) == 0) {
      return 8;
    }
  }
  return 2;
}

// FUNCTION: IMPERIALISM 0x004a4ad0
undefined TArmyMgr::HandleMapClickByCivilianCursorState(short tileIndex, short mode) {
  int cursorState = this->ComputeCivilianMapCursorStateIndex(tileIndex, mode);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  switch (cursorState) {
  case 2:
    this->SetActiveProvinceSelection(cityRecordIndex);
    return 0;
  case 3:
  case 4:
    break;
  case 5:
    return this->ValidateOrderPlacementPrerequisitesForSelectedTile(cityRecordIndex);
  case 6:
    this->SetActiveProvinceAndBuildDirectionalOrderOverlays(tileIndex);
    return 0;
  case 7:
    g_pUiRuntimeContext->HandleTurnEventDialogFactorySlotEC(this->pendingMapActionIndex);
    return 0;
  case 8:
    this->BuildMapHintOverlayTextAndDispatchUiMessages(cityRecordIndex);
    // fall through
  default:
    return 0;
  }

  const TGlobalMapCityScoreRecord& selectedTile =
      g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex];
  bool cityIsAdjacent = false;
  for (short i = 0; i < selectedTile.adjacentRegionCount08; ++i) {
    if (selectedTile.adjacentRegionIds0A[i] == cityRecordIndex) {
      cityIsAdjacent = true;
      break;
    }
  }
  if (cityIsAdjacent) {
    return this->SelectMovableUnitOnCurrentTileAndPlaySfx(cityRecordIndex);
  }
  return this->CommitCityActionGateCostIfAffordable(cityRecordIndex);
}

// FUNCTION: IMPERIALISM 0x004a4c80
int TArmyMgr::ComputeCivilianMapCursorStateIndex(short tileIndex, short mode) {
  if (this->pendingMapActionIndex == -1) {
    return ComputeMapCursorStateIndex(tileIndex, mode);
  }

  TTerrainStateRecordView* rec = &g_pGlobalMapState->terrainStateTable[tileIndex];
  if (rec->perTileVisitedFlag0f > 0) {
    return 6;
  }
  short cityRecordIndex = rec->cityRecordIndex;
  if (cityRecordIndex == -1) {
    return 1;
  }

  short pendingSlot =
      g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(this->pendingMapActionIndex);
  short citySlot = g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(cityRecordIndex);

  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  bool hasMovableUnit = false;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
    if (unit->field_8 == 0 && unit->GetUnitMovementClassId() != 0) {
      hasMovableUnit = true;
      break;
    }
  }

  if (cityRecordIndex == this->pendingMapActionIndex) {
    return ((rec->activeFlags1c >> 5) & 1) != 0 ? 7 : 0;
  }

  bool sameOwner = pendingSlot == citySlot;
  if (!sameOwner) {
    TCountry* cityOwnerCountry = g_apTerrainTypeDescriptorTable[citySlot];
    sameOwner = cityOwnerCountry->IsEncodedNationSlotMinus200Equal(pendingSlot) != 0;
  }

  if (sameOwner) {
    if (((rec->activeFlags1c >> 5) & 1) != 0) {
      return 2;
    }
    if (!hasMovableUnit) {
      return 1;
    }
    return g_pGlobalMapState->TileHasMovementClassId(this->pendingMapActionIndex, cityRecordIndex)
               ? 3
               : 4;
  }

  if (((rec->activeFlags1c >> 5) & 1) != 0) {
    return 8;
  }
  if (!hasMovableUnit) {
    return 1;
  }
  if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(pendingSlot, citySlot)) {
    return 1;
  }
  if (g_pGlobalMapState->TileHasMovementClassId(this->pendingMapActionIndex, cityRecordIndex)) {
    return 5;
  }
  if ((g_pGlobalMapState->cityScoreTable[cityRecordIndex].exploredByNationMaskA1 >> pendingSlot) &
      1) {
    return 5;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004a5080
bool TArmyMgr::ValidateOrderPlacementPrerequisitesForSelectedTile(short cityRecordIndex) {
  // TODO: port body @ 0x4a5080 (1407 bytes; large, not yet ported).
  (void)cityRecordIndex;
  return false;
}

// FUNCTION: IMPERIALISM 0x004a5760
void TArmyMgr::SetActiveProvinceAndBuildDirectionalOrderOverlays(short tileIndex) {
  // TODO: port body @ 0x4a5760 (656 bytes; builds directional order-overlay controls from
  // the tile's adjacent-region list; not yet ported).
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x004a5b10
void TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup(TArmyStack* ourStack,
                                                                TArmyStack* enemyStack,
                                                                int ownerNationCodeInt) {
  // TODO: port body @ 0x4a5b10 (243 bytes; SEH-framed; not yet ported).
  (void)ourStack;
  (void)enemyStack;
  (void)ownerNationCodeInt;
}

// FUNCTION: IMPERIALISM 0x004a6680
void TArmyMgr::BuildMapHintOverlayTextAndDispatchUiMessages(short cityRecordIndex) {
  // TODO: port body @ 0x4a6680 (1372 bytes; heavy CString-based UI hint-text composition;
  // not yet ported).
  (void)cityRecordIndex;
}
