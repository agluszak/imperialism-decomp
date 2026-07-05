#include "game/TArmyMgr.h"

#include "game/CIterator.h"
#include "game/TCountry.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/TSortedList.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h" // g_pSimMgr, g_pGlobalMapState, g_apTerrainTypeDescriptorTable, g_pSfxPlaybackSystem
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004a1810
// TArmyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a1850
// TArmyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyMgr, TObject)

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
undefined TArmyMgr::Helper_Uses_GenerateThreadLocalRandom15_At004a35e0(int param_1, short param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a37b0
undefined TArmyMgr::OrphanCallChain_C2_I40_004a37b0(int param_1) {
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
undefined TArmyMgr::CommitCityActionGateCostIfAffordable(int contextArg) {
  (void)contextArg;
  return 0;
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
