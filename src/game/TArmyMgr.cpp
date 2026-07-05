#include "game/TArmyMgr.h"

#include "game/CIterator.h"
#include "game/CString.h"
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

namespace {
// Provisional shape for the unit-order queue reached through TArmyMgr's slots 0x0f/0x10
// (concrete owning class not recovered -- see the header declarations, Hard Rule 12).
struct UnitOrderQueueNode {
  TUnit* unit;              // +0x00
  UnitOrderQueueNode* next; // +0x04
};
struct UnitOrderQueueCursor {
  unsigned char pad00[0x10];
  short targetProvinceId; // +0x10
  unsigned char pad12[2];
  UnitOrderQueueNode* head;   // +0x14
  UnitOrderQueueNode* cursor; // +0x18
};
} // namespace

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
    this->OrphanCallChain_C12_I108_004a2390();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a1f80
undefined TArmyMgr::ProcessTileUnitListsAndApplyRandomStatusUpdates() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a2390
undefined TArmyMgr::OrphanCallChain_C12_I108_004a2390() {
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
undefined TArmyMgr::TryCreateTacticalBattleViewForTileArmies() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a35e0
undefined TArmyMgr::RedistributeUnitOrderQueueToRandomAdjacentRegion(void* unitQueue,
                                                                     short tileIndex) {
  UnitOrderQueueCursor* queue = static_cast<UnitOrderQueueCursor*>(unitQueue);
  queue->cursor = queue->head;
  TUnit* headUnit = (queue->head != nullptr) ? queue->head->unit : nullptr;
  short headUnitTag = headUnit->field_18;

  const TGlobalMapCityScoreRecord& record = g_pGlobalMapState->cityScoreTable[tileIndex];
  short candidateRegions[12];
  int candidateCount = 0;
  for (int i = 0; i < 0x18; ++i) {
    short regionId = record.adjacentRegionIds0A[i];
    if (regionId == -1) {
      break;
    }
    if ((&this->regionAffinityTable1c)[regionId] == headUnitTag) {
      candidateRegions[candidateCount] = regionId;
      ++candidateCount;
    }
  }

  if (candidateCount == 0) {
    queue->cursor = queue->head;
    UnitOrderQueueNode* node = queue->cursor;
    TUnit* unit = (node != nullptr) ? node->unit : nullptr;
    while (unit != nullptr) {
      if (static_cast<TMilitaryUnit*>(unit)->field_34 != 0) {
        unit->DetachUnitOrderFromOwnerAndReset();
      }
      node = queue->cursor;
      if (node != nullptr) {
        node = node->next;
        queue->cursor = node;
        unit = (node != nullptr) ? node->unit : nullptr;
      } else {
        unit = nullptr;
      }
    }
    return 0;
  }

  short chosenRegion = candidateRegions[GenerateThreadLocalRandom15() % candidateCount];
  queue->cursor = queue->head;
  UnitOrderQueueNode* node = queue->cursor;
  TUnit* unit = (node != nullptr) ? node->unit : nullptr;
  while (unit != nullptr) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->orderType] == 0) {
      unit->DetachUnitOrderFromOwnerAndReset();
    } else {
      unit->SetOrderModeSlot34(1, chosenRegion);
    }
    node = queue->cursor;
    if (node != nullptr) {
      node = node->next;
      queue->cursor = node;
      unit = (node != nullptr) ? node->unit : nullptr;
    } else {
      unit = nullptr;
    }
  }

  queue->cursor = queue->head;
  node = queue->cursor;
  unit = (node != nullptr) ? node->unit : nullptr;
  if (unit == nullptr) {
    return 0;
  }
  do {
    unit->VTableSlot10(unit->field_C);
    unit->SetOrderModeSlot34(0, -1);
    node = queue->cursor;
    if (node != nullptr) {
      node = node->next;
      queue->cursor = node;
      unit = (node != nullptr) ? node->unit : nullptr;
    } else {
      unit = nullptr;
    }
  } while (unit != nullptr);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a37b0
undefined TArmyMgr::ResetAndRelocateUnitOrderQueue_004a37b0(void* param_1) {
  UnitOrderQueueCursor* queue = static_cast<UnitOrderQueueCursor*>(param_1);
  queue->cursor = queue->head;
  UnitOrderQueueNode* node = queue->cursor;
  TUnit* unit = (node != nullptr) ? node->unit : nullptr;
  while (unit != nullptr) {
    unit->SetOrderModeSlot34(0, -1);
    if (unit->field_6 != queue->targetProvinceId) {
      unit->VTableSlot10(queue->targetProvinceId);
    }
    node = queue->cursor;
    if (node != nullptr) {
      node = node->next;
      queue->cursor = node;
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
