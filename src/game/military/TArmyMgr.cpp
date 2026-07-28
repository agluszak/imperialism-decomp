#include "game/military/TArmyMgr.h"
#include "game/military/TArmyStackList.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TWindow.h"
#include "game/assets/TAssetMgr.h"
#include "game/TEvent.h"
#include "game/ui_core/TStaticText.h"
#include "game/turn_event_dialog_provisional.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"

#include <stdlib.h>
#include <string.h>

#include "game/TList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/map_order_battle_snapshot.h"

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/tactical/TArmyBattle.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/military/TArmyStack.h"
#include "game/ui_core/TControl.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/military/TMilitaryUnit.h"
#include "game/navy/TAdmiral.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h" // scanBracketExpressions
#include "game/navy_order.h" // g_pNavyPrimaryOrderListHead, FindCumulativeWeightBucketIndex
#include "game/ui_core/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// reservedByte03/actionType04/tileOrObject08 read up front; nationIds[1] is read later,
// interleaved into the per-side loop below alongside nationIds[0]), resolving
// tileOrObject08 either as a raw tile/record index (actionType04 in {0,3,4}) or, via
// FindMapActionContextByNodeId, a live TZone* -- mirrors the port-zone/context-array
// two-way match idiom used throughout TZone.cpp. Then for each side (0/1), reads the
// nation-id byte, the fixed name/overlay buffers (a version-gated legacy string read
// pre-0x2c, plain fixed-size reads from 0x2c on), the child-record count, and
// (re)allocates + reads that many MapOrderBattleSideChildRecord entries.
// FUNCTION: IMPERIALISM 0x004a13c0
void MapContextActionRecord::ReadFrom(TStream* stream) {
  stream->ReadBytes(&participantIndex02, 1);
  stream->ReadBytes(&reservedByte03, 1);
  stream->ReadBytes(&actionType04, 4);
  short nodeId;
  stream->ReadBytes(&nodeId, 2);
  if (actionType04 == 0 || actionType04 == 3 || actionType04 == 4) {
    tileOrObject08.tileIndex = nodeId;
  } else {
    tileOrObject08.object = FindMapActionContextByNodeId(nodeId);
  }

  for (int side = 0; side < 2; ++side) {
    stream->ReadBytes(&nationIds[side], 1);
    if (g_nSaveFormatVersion < 0x2c) {
      stream->ReadString(nameBuffer0c[side].data, 0x20);
      stream->ReadString(overlayLabel4c[side].data, 0xff);
    } else {
      stream->ReadBytes(nameBuffer0c[side].data, 0x20);
      stream->ReadBytes(overlayLabel4c[side].data, 0xff);
    }
    stream->ReadBytes(&childCount24a[side], 2);

    delete[] sideChildRecords250[side];
    short count = childCount24a[side];
    MapOrderBattleSideChildRecord* newArray = new MapOrderBattleSideChildRecord[count];
    sideChildRecords250[side] = newArray;

    for (int j = 0; j < childCount24a[side]; ++j) {
      MapOrderBattleSideChildRecord& elem = sideChildRecords250[side][j];
      stream->ReadBytes(&elem.resourceType, 2);
      stream->ReadBytes(&elem.stockOrRequired, 2);
      if (g_nSaveFormatVersion < 0x2c) {
        stream->ReadString(&elem.nameBuffer, 0x20);
      } else {
        stream->ReadBytes(&elem.nameBuffer, 0x20);
      }
      stream->ReadBytes(&elem.strengthBucket, 2);
      stream->ReadBytes(&elem.detailIdentity, 4);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a1640
void MapContextActionRecord::WriteTo(TStream* stream) {
  stream->WriteBytes(&participantIndex02, 1);
  stream->WriteBytes(&reservedByte03, 1);
  stream->WriteBytes(&actionType04, 4);

  short nodeId;
  if (actionType04 == 0 || actionType04 == 3 || actionType04 == 4) {
    nodeId = static_cast<short>(tileOrObject08.tileIndex);
  } else {
    nodeId = static_cast<TZone*>(tileOrObject08.object)->GetContextOrdinalOrInvalid();
  }
  stream->WriteBytes(&nodeId, 2);

  for (int side = 0; side < 2; ++side) {
    stream->WriteBytes(&nationIds[side], 1);
    stream->WriteBytes(nameBuffer0c[side].data, 0x20);
    stream->WriteBytes(overlayLabel4c[side].data, 0xff);
    stream->WriteBytes(&childCount24a[side], 2);
    for (int i = 0; i < childCount24a[side]; ++i) {
      MapOrderBattleSideChildRecord& child = sideChildRecords250[side][i];
      stream->WriteBytes(&child.resourceType, 2);
      stream->WriteBytes(&child.stockOrRequired, 2);
      stream->WriteBytes(child.nameBuffer, 0x20);
      stream->WriteBytes(&child.strengthBucket, 2);
      stream->WriteBytes(&child.detailIdentity, 4);
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x004a1810
// TArmyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a1850
// TArmyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyMgr, TObject)

// Own-source function (not a TArmyMgr method -- ground truth doesn't touch `this`).
// Classifies a map-click as: 6 (already visited this pass), 0 (blocked -- dialog/order
// context active, or tile already has a pending civilian order), 8 (blocked -- active
// nation not eligible, or a diplomacy-target mismatch with the tile's owner), or 2
// (click accepted). Defined below (0x4a4960) in address order; forward-declared here
// for HandleMapClickByComputedCursorState's use.
static int __stdcall ComputeMapCursorStateIndex(short tileIndex, short mode);

// Reads one action-record from `stream`: the fixed header fields (nationIds[0] and

// FUNCTION: IMPERIALISM 0x004a1870
TArmyMgr::TArmyMgr() {
  pendingMapActionIndex = -1;
  mapContextActionRecordList04 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004a18a0
// TArmyMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004a18d0
TArmyMgr::~TArmyMgr() {}

// FUNCTION: IMPERIALISM 0x004a18f0
void TArmyMgr::IArmyMgr() {
  pendingUnitPool0c = new TArmyStackList();
  staticTable14 = g_MapContextStaticTable_00695448;
  staticTable18 = g_MapContextStaticTable_00695428;
  needsTerrainRefreshFlag39a = 0;
  ourStackBattle39c = 0;
  enemyStackBattle3a0 = 0;
  activeBattleView3a4 = 0;
  mapContextActionRecordList04 = new TSortedPtrList();
  mapContextActionRecordList04->recordSize14 = sizeof(MapContextActionRecord);
  flag8 = 0;
}

// FUNCTION: IMPERIALISM 0x004a1a00
void TArmyMgr::Free() {
  if (pendingUnitPool0c != 0) {
    pendingUnitPool0c->FreePayloadsAndDestroy();
  }
  pendingUnitPool0c = 0;

  if (mapContextActionRecordList04 != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords250[0];
      delete[] record->sideChildRecords250[1];
      record->sideChildRecords250[1] = 0;
      record->sideChildRecords250[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList04->ClearAndFreeAllPtrListRecords();
  }
  flag8 = 0;

  if (mapContextActionRecordList04 != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords250[0];
      delete[] record->sideChildRecords250[1];
      record->sideChildRecords250[1] = 0;
      record->sideChildRecords250[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList04->ReleasePtrList();
  }

  if (ourStackBattle39c != 0) {
    ourStackBattle39c->Free();
  }
  ourStackBattle39c = 0;
  if (enemyStackBattle3a0 != 0) {
    enemyStackBattle3a0->Free();
  }
  enemyStackBattle3a0 = 0;
  if (activeBattleView3a4 != 0) {
    activeBattleView3a4->Free();
  }
  activeBattleView3a4 = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x004a1b80
void TArmyMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  // The null test and the final clear go through `this`, but the purge walk reloads the
  // manager singleton on every iteration (0x4a1bb7/0x4a1bc6 read [0x006a3338] rather than
  // EBP) -- the same asymmetry TArmyMgr::Free shows, so it is written the same way here.
  if (mapContextActionRecordList04 != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords250[0];
      delete[] record->sideChildRecords250[1];
      record->sideChildRecords250[1] = 0;
      record->sideChildRecords250[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList04->ClearAndFreeAllPtrListRecords();
  }
  flag8 = 0;
  if (g_nSaveFormatVersion >= 0x25) {
    int count = stream->ReadInteger();
    while (count-- != 0) {
      // The two stride-0x20 / stride-0xff store loops at 0x4a1c47 and 0x4a1c58 are the
      // array default-construction of nameBuffer0c and overlayLabel4c, emitted by this
      // declaration; only the POD tail needs clearing by hand.
      MapContextActionRecord record;
      record.childCount24a[1] = 0;
      record.childCount24a[0] = 0;
      record.sideChildRecords250[1] = 0;
      record.sideChildRecords250[0] = 0;

      record.ReadFrom(stream);
      mapContextActionRecordList04->AppendCopiedRecordToPtrList(&record);
      flag8 = 1;
      // Redundant re-store (both branches write the same 1); preserved to match codegen
      // (same idiom as AppendMapContextActionRecordAndResetWorkingFields, which reads the
      // same byte global at 0x006a42dc).
      if (g_bRandomMapDeveloperCheatFlag != 0) {
        flag8 = 1;
      }

      // The copied record in the list now owns these arrays; reset our local's copies
      // (ground truth re-zeroes them here too, matching the ctor-time defaults).
      record.sideChildRecords250[1] = 0;
      record.sideChildRecords250[0] = 0;
      record.childCount24a[1] = 0;
      record.childCount24a[0] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a1dd0
void TArmyMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  int count = mapContextActionRecordList04->GetSize();
  stream->WriteInteger(count);
  for (int index = 0; index < mapContextActionRecordList04->GetSize(); ++index) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(index + 1));
    record->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x004a1e40
void TArmyMgr::DoCombatMoves() {
  // g_pSimMgr->multiplayerSessionRole is the multiplayer-mode dword (compared against 1/2
  // throughout TMultiplayerMgr.cpp); == 2 selects the alternate branch here. The test is
  // materialized into a byte Boolean before it is branched on -- 0x4a1e49's
  // xor/cmp/setz/test al pair is an unsigned char local, not a direct `if` on the compare.
  unsigned char isNetworkClient = (g_pSimMgr->multiplayerSessionRole == 2);
  if (isNetworkClient) {
    this->ClearPendingStacksAndFinalizeMilitaryUnits();
    g_pSimMgr->StartNextPhase();
  } else {
    this->FormStacks();
    this->nextStackOrdinal10 = 1;
    this->ResolveNextMove();
  }
}

// FUNCTION: IMPERIALISM 0x004a1eb0
void TArmyMgr::EndBattlePhase() {
  if (this->ourStackBattle39c != nullptr) {
    this->ourStackBattle39c->Free();
  }
  this->ourStackBattle39c = nullptr;
  if (this->enemyStackBattle3a0 != nullptr) {
    this->enemyStackBattle3a0->Free();
  }
  this->enemyStackBattle3a0 = nullptr;
  if (this->activeBattleView3a4 != nullptr) {
    this->activeBattleView3a4->Free();
  }
  this->activeBattleView3a4 = nullptr;

  this->ClearPendingStacksAndFinalizeMilitaryUnits();
  this->DoOwnershipChanges();

  if (this->needsTerrainRefreshFlag39a != 0) {
    g_pMacViewMgr->RebuildNationClipRegionsAndDispatchMapEvent();
    for (int i = 0; i < kTerrainTypeDescriptorTableCount; ++i) {
      if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
        g_apTerrainTypeDescriptorTable[i]->SetSerializedField8c(-1);
      }
    }
  }
  this->needsTerrainRefreshFlag39a = 0;
  g_pSimMgr->StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x004a1f80
void TArmyMgr::FormStacks() {
  TArmyStack* stack = nullptr;
  for (int tileIndex = 0; tileIndex < 0x180; ++tileIndex) {
    TUnit* unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
    short previousOrderTargetIndex = -1;
    short previousOwnerNationSlot = -1;
    for (; unit != nullptr; unit = unit->nextAtLocation14) {
      short unitOrderTargetIndex = unit->orderTargetIndex0C;
      short unitOwnerNationSlot = unit->ownerNationSlot18;
      if (unitOrderTargetIndex == -1) {
        TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
        if (milUnit->strength34 < 0x191) {
          milUnit->strength34 += 100;
        } else {
          milUnit->strength34 = 500;
        }
        if (unitOwnerNationSlot < 7 &&
            g_apNationStates[unitOwnerNationSlot]->diplomacyEligibilityA0 == 0) {
          unit->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        continue;
      }

      if (unitOrderTargetIndex != previousOrderTargetIndex ||
          unitOwnerNationSlot != previousOwnerNationSlot || stack == nullptr) {
        bool foundExisting = false;
        int count = this->pendingUnitPool0c->GetCount();
        if (count != 0) {
          int index = 1;
          count = this->pendingUnitPool0c->GetCount();
          if (index <= count) {
            do {
              if (foundExisting) {
                break;
              }
              stack = static_cast<TArmyStack*>(this->pendingUnitPool0c->GetEntryByOrdinal(index));
              stack->AssertValid();
              if (stack->ownerNationCodeE == unitOrderTargetIndex &&
                  static_cast<short>(stack->categoryFlag8) == unitOwnerNationSlot) {
                foundExisting = true;
              } else {
                ++index;
              }
              count = this->pendingUnitPool0c->GetCount();
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
          stack->categoryFlag8 = static_cast<unsigned char>(unitOwnerNationSlot);
          stack->fieldC = 0;
          stack->ownerNationCodeE = unitOrderTargetIndex;
          stack->tileIndex10 = static_cast<short>(tileIndex);
          this->pendingUnitPool0c->listState.AddHead(stack);
        }
        previousOrderTargetIndex = unitOrderTargetIndex;
        previousOwnerNationSlot = unitOwnerNationSlot;
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
    int roll = rand();
    item->field6 = static_cast<short>((item->field4 << 8) + (roll & 0xff));
  }

  this->pendingUnitPool0c->Sort();
  for (int i = 0; i < 0x180; ++i) {
    this->perTileOwnerNationCodeCache1c[i] =
        g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(i);
  }
}

// FUNCTION: IMPERIALISM 0x004a2390
void TArmyMgr::ResolveNextMove() {
  bool battleViewCreated = false;
  if (this->ourStackBattle39c != nullptr) {
    this->ourStackBattle39c->Free();
  }
  this->ourStackBattle39c = nullptr;
  if (this->enemyStackBattle3a0 != nullptr) {
    this->enemyStackBattle3a0->Free();
  }
  this->enemyStackBattle3a0 = nullptr;
  if (this->activeBattleView3a4 != nullptr) {
    this->activeBattleView3a4->Free();
  }
  this->activeBattleView3a4 = nullptr;

  int stackCount = this->pendingUnitPool0c->GetCount();
  if (this->nextStackOrdinal10 <= stackCount) {
    do {
      int cursor = this->nextStackOrdinal10;
      stackCount = this->pendingUnitPool0c->GetCount();
      if (stackCount < cursor) {
        break;
      }
      this->nextStackOrdinal10 = cursor + 1;
      TArmyStack* stack =
          static_cast<TArmyStack*>(this->pendingUnitPool0c->GetEntryByOrdinal(cursor));
      stack->AssertValid();
      if (this->perTileOwnerNationCodeCache1c[stack->ownerNationCodeE] ==
          static_cast<short>(stack->categoryFlag8)) {
        stack->cursor18 = stack->head14;
        TArmyStackUnitNode* node = stack->cursor18;
        TUnit* unit = (node != nullptr) ? node->unit : nullptr;
        while (unit != nullptr) {
          unit->MoveTo(unit->orderTargetIndex0C);
          unit->SetOrders(kUnitOrderIdle, -1);
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
    stackCount = this->pendingUnitPool0c->GetCount();
    if (this->nextStackOrdinal10 <= stackCount) {
      return;
    }
    if (battleViewCreated) {
      return;
    }
  }
  this->EndBattlePhase();
}

// FUNCTION: IMPERIALISM 0x004a2500
void TArmyMgr::ClearPendingStacksAndFinalizeMilitaryUnits() {
  this->pendingUnitPool0c->FreePayloads();
  g_pGlobalMapState->DimmingOff();

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
      if (unit->strength34 > 0 && unit->tileIndex06 != -1) {
        unit->ContinueOrders();
      } else {
        unit->DetachUnitOrderFromOwnerAndReset();
        unit->Free();
      }
    }
  }
}

static inline void CopyTextIntoFixedBuffer(char* destination, int capacity, const char* source) {
  int index = 0;
  while (index < capacity) {
    char value = source[index];
    destination[index] = value;
    if (value == 0) {
      break;
    }
    ++index;
  }
}

static inline void AppendTextIntoFixedBuffer(char* destination, int capacity, const char* source) {
  int index = 0;
  while (index < capacity && destination[index] != 0) {
    ++index;
  }
  while (index < capacity) {
    char value = *source;
    destination[index] = value;
    if (value == 0) {
      break;
    }
    ++index;
    ++source;
  }
}

// Add one localized army-unit count fragment to a fixed-capacity context label.
// FUNCTION: IMPERIALISM 0x004a2610
static void BuildArmyActionLabelFromLocalizationAndCounts(CStr255* destination, int count,
                                                          int activeCount, int unitTypeIndex) {
  if (count == 0) {
    return;
  }

  CString formattedLabel;
  CString unitTypeName;
  CString countText;
  g_pSimMgr->GetString(0x2717, unitTypeIndex, &unitTypeName);
  countText.Format(g_szDecimalFormat, count);

  if (count == activeCount) {
    scanBracketExpressions(g_pSimMgr, &formattedLabel, "[1] [2]", static_cast<LPCSTR>(countText),
                           static_cast<LPCSTR>(unitTypeName));
  } else {
    CString inactiveCountText;
    CString inactiveLabel;
    inactiveCountText.Format(g_szDecimalFormat, count - activeCount);
    g_pSimMgr->GetString(0x273d, 0xb, &inactiveLabel);
    scanBracketExpressions(g_pSimMgr, &formattedLabel, "[1] [2] ([3] [4])",
                           static_cast<LPCSTR>(countText), static_cast<LPCSTR>(unitTypeName),
                           static_cast<LPCSTR>(inactiveCountText),
                           static_cast<LPCSTR>(inactiveLabel));
  }

  bool destinationHasText;
  {
    CString currentLabel;
    currentLabel = destination->data;
    destinationHasText = currentLabel.Compare(g_szEmptyString) != 0;
  }
  if (destinationHasText) {
    CString separator(g_szListSeparator_00695760);
    AppendTextIntoFixedBuffer(destination->data, 0xff, static_cast<LPCSTR>(separator));
  }
  AppendTextIntoFixedBuffer(destination->data, 0xff, static_cast<LPCSTR>(formattedLabel));
}

// Own-source function (not a TArmyMgr method -- its callsites push all five arguments,
// it never reads ECX as a receiver, and it returns with a bare RET).
// FUNCTION: IMPERIALISM 0x004a2900
static void BuildArmyContextActionRecordsAndDispatchLabel(TArmyStack* ourStack,
                                                          TArmyStack* enemyStack,
                                                          unsigned char sideWonFlag,
                                                          int ownerNationCodeInt, int unused) {
  (void)unused;

  MapContextActionRecord record;
  record.childCount24a[1] = 0;
  record.childCount24a[0] = 0;
  record.sideChildRecords250[1] = 0;
  record.sideChildRecords250[0] = 0;
  record.nationIds[1] = enemyStack->categoryFlag8;
  record.nationIds[0] = ourStack->categoryFlag8;
  record.tileOrObject08.raw = ownerNationCodeInt;
  record.actionType04 = 0;
  record.reservedByte03 = 0;

  if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
          ourStack->categoryFlag8, enemyStack->categoryFlag8)) {
    record.actionType04 = 3;
  } else if (enemyStack->ResetCursorAndGetHeadUnit() == 0) {
    record.actionType04 = 4;
  }

  const int kUnitTypeSlotCount = 30;
  int ourCount[kUnitTypeSlotCount] = {0};
  int ourActiveCount[kUnitTypeSlotCount] = {0};
  int enemyCount[kUnitTypeSlotCount] = {0};
  int enemyActiveCount[kUnitTypeSlotCount] = {0};
  TMilitaryUnit* ourBestUnit = 0;
  for (TUnit* unit = ourStack->ResetCursorAndGetHeadUnit(); unit != 0;
       unit = ourStack->AdvanceCursorAndGetUnit()) {
    ++record.childCount24a[0];
    ++ourCount[unit->orderType];
    TMilitaryUnit* militaryUnit = static_cast<TMilitaryUnit*>(unit);
    if (militaryUnit->strength34 > 0) {
      ++ourActiveCount[unit->orderType];
    }
    if (unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1) &&
        (ourBestUnit == 0 ||
         militaryUnit->experiencePercent38 / 100 > ourBestUnit->experiencePercent38 / 100)) {
      ourBestUnit = militaryUnit;
    }
  }

  TMilitaryUnit* enemyBestUnit = 0;
  for (TUnit* enemyUnit = enemyStack->ResetCursorAndGetHeadUnit(); enemyUnit != 0;
       enemyUnit = enemyStack->AdvanceCursorAndGetUnit()) {
    ++record.childCount24a[1];
    ++enemyCount[enemyUnit->orderType];
    TMilitaryUnit* militaryUnit = static_cast<TMilitaryUnit*>(enemyUnit);
    if (militaryUnit->strength34 > 0) {
      ++enemyActiveCount[enemyUnit->orderType];
    }
    if (enemyUnit->orderType >= EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1) &&
        (enemyBestUnit == 0 ||
         militaryUnit->experiencePercent38 / 100 > enemyBestUnit->experiencePercent38 / 100)) {
      enemyBestUnit = militaryUnit;
    }
  }

  delete[] record.sideChildRecords250[0];
  record.sideChildRecords250[0] = new MapOrderBattleSideChildRecord[record.childCount24a[0]];
  delete[] record.sideChildRecords250[1];
  record.sideChildRecords250[1] = new MapOrderBattleSideChildRecord[record.childCount24a[1]];

  int childIndex = 0;
  for (TUnit* ourRecordUnit = ourStack->ResetCursorAndGetHeadUnit(); ourRecordUnit != 0;
       ourRecordUnit = ourStack->AdvanceCursorAndGetUnit()) {
    TMilitaryUnit* militaryUnit = static_cast<TMilitaryUnit*>(ourRecordUnit);
    MapOrderBattleSideChildRecord& child = record.sideChildRecords250[0][childIndex];
    child.resourceType = ourRecordUnit->orderType;
    child.stockOrRequired = militaryUnit->strength34;
    if (child.stockOrRequired == -86) {
      child.stockOrRequired = 0;
    }
    CString unitName;
    unitName = militaryUnit->name24;
    CopyTextIntoFixedBuffer(child.nameBuffer, 0x20, static_cast<LPCSTR>(unitName));
    child.detailIdentity.categoryTag = kControlTagArmy;
    child.strengthBucket = static_cast<short>(militaryUnit->experiencePercent38 / 100);
    ++childIndex;
  }

  childIndex = 0;
  for (TUnit* enemyRecordUnit = enemyStack->ResetCursorAndGetHeadUnit(); enemyRecordUnit != 0;
       enemyRecordUnit = enemyStack->AdvanceCursorAndGetUnit()) {
    TMilitaryUnit* militaryUnit = static_cast<TMilitaryUnit*>(enemyRecordUnit);
    MapOrderBattleSideChildRecord& child = record.sideChildRecords250[1][childIndex];
    child.resourceType = enemyRecordUnit->orderType;
    child.stockOrRequired = militaryUnit->strength34;
    if (child.stockOrRequired == -86) {
      child.stockOrRequired = 0;
    }
    CString unitName;
    unitName = militaryUnit->name24;
    CopyTextIntoFixedBuffer(child.nameBuffer, 0x20, static_cast<LPCSTR>(unitName));
    child.detailIdentity.categoryTag = kControlTagArmy;
    child.strengthBucket = static_cast<short>(militaryUnit->experiencePercent38 / 100);
    ++childIndex;
  }

  CString formattedName;
  CString nationName;
  CString nameTemplate;
  g_pSimMgr->GetString(0x273d, 0x10, &nameTemplate);
  g_apTerrainTypeDescriptorTable[ourStack->categoryFlag8]->FormatOverlayTerrainLabelText(
      &nationName);
  scanBracketExpressions(g_pSimMgr, &formattedName, static_cast<LPCSTR>(nameTemplate),
                         static_cast<LPCSTR>(nationName));
  CopyTextIntoFixedBuffer(record.nameBuffer0c[0].data, 0x20, static_cast<LPCSTR>(formattedName));

  g_pSimMgr->GetString(0x273d, 0x11, &nameTemplate);
  g_apTerrainTypeDescriptorTable[enemyStack->categoryFlag8]->FormatOverlayTerrainLabelText(
      &nationName);
  scanBracketExpressions(g_pSimMgr, &formattedName, static_cast<LPCSTR>(nameTemplate),
                         static_cast<LPCSTR>(nationName));
  CopyTextIntoFixedBuffer(record.nameBuffer0c[1].data, 0x20, static_cast<LPCSTR>(formattedName));

  CopyTextIntoFixedBuffer(record.overlayLabel4c[1].data, 0xff, g_szEmptyString);
  CopyTextIntoFixedBuffer(record.overlayLabel4c[0].data, 0xff, record.overlayLabel4c[1].data);
  record.participantIndex02 = sideWonFlag == 0;

  for (int unitTypeIndex = 0; unitTypeIndex < kUnitTypeSlotCount; ++unitTypeIndex) {
    BuildArmyActionLabelFromLocalizationAndCounts(&record.overlayLabel4c[0],
                                                  ourCount[unitTypeIndex],
                                                  ourActiveCount[unitTypeIndex], unitTypeIndex);
    BuildArmyActionLabelFromLocalizationAndCounts(&record.overlayLabel4c[1],
                                                  enemyCount[unitTypeIndex],
                                                  enemyActiveCount[unitTypeIndex], unitTypeIndex);
  }

  g_pMapContextActionManager->mapContextActionRecordList04->AppendCopiedRecordToPtrList(&record);
  record.sideChildRecords250[1] = 0;
  record.sideChildRecords250[0] = 0;
  record.childCount24a[1] = 0;
  record.childCount24a[0] = 0;
  g_pMapContextActionManager->flag8 = 1;
  if (g_bRandomMapDeveloperCheatFlag != 0) {
    g_pMapContextActionManager->flag8 = 1;
  }

  (void)ourBestUnit;
  (void)enemyBestUnit;
}

// FUNCTION: IMPERIALISM 0x004a3200
bool TArmyMgr::TryCreateTacticalBattleViewForTileArmies(TArmyStack* stack, short ownerNationCode) {
  bool tacticalViewCreated = false;
  TArmyStackUnitNode* headNode = stack->head14;
  stack->cursor18 = headNode;
  TUnit* curUnit = (headNode != nullptr) ? headNode->unit : nullptr;

  // Partition stack's own unit chain into a new "our stack" containing only the units
  // whose orderTargetIndex0C (order-owner nation) matches ownerNationCode; stack->head14 itself is
  // left untouched, only its cursor18 iteration state advances.
  TArmyStack* ourStack = new TArmyStack();
  ourStack->head14 = nullptr;
  ourStack->cursor18 = nullptr;
  ourStack->categoryFlag8 = static_cast<unsigned char>(curUnit->ownerNationSlot18);
  ourStack->fieldA = 0;
  ourStack->field6 = 0;
  ourStack->field4 = 0;
  ourStack->fieldC = 0;
  ourStack->ownerNationCodeE = ownerNationCode;
  ourStack->tileIndex10 = curUnit->tileIndex06;

  while (curUnit != nullptr) {
    if (curUnit->orderTargetIndex0C == ownerNationCode) {
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
    for (; enemyUnit != nullptr;
         enemyUnit = static_cast<TMilitaryUnit*>(enemyUnit->nextAtLocation14)) {
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
      this->RelocateStackUnitsToStackTile(ourStack);
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
        unit->MoveTo(unit->orderTargetIndex0C);
        unit->SetOrders(kUnitOrderIdle, -1);
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
void TArmyMgr::RedistributeUnitOrderQueueToRandomAdjacentRegion(TArmyStack* stack,
                                                                short tileIndex) {
  stack->cursor18 = stack->head14;
  TUnit* headUnit = (stack->head14 != nullptr) ? stack->head14->unit : nullptr;
  short headUnitTag = headUnit->ownerNationSlot18;

  const Province& record = g_pGlobalMapState->cityScoreTable[tileIndex];
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
      if (static_cast<TMilitaryUnit*>(unit)->strength34 != 0) {
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
    return;
  }

  short chosenRegion = candidateRegions[rand() % candidateCount];
  stack->cursor18 = stack->head14;
  TArmyStackUnitNode* node = stack->cursor18;
  TUnit* unit = (node != nullptr) ? node->unit : nullptr;
  while (unit != nullptr) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->orderType] == 0) {
      unit->DetachUnitOrderFromOwnerAndReset();
    } else {
      unit->SetOrders(kUnitOrderRedeploy, chosenRegion);
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
    return;
  }
  do {
    unit->MoveTo(unit->orderTargetIndex0C);
    unit->SetOrders(kUnitOrderIdle, -1);
    node = stack->cursor18;
    if (node != nullptr) {
      node = node->next;
      stack->cursor18 = node;
      unit = (node != nullptr) ? node->unit : nullptr;
    } else {
      unit = nullptr;
    }
  } while (unit != nullptr);
}

// FUNCTION: IMPERIALISM 0x004a37b0
void TArmyMgr::RelocateStackUnitsToStackTile(TArmyStack* stack) {
  stack->cursor18 = stack->head14;
  TArmyStackUnitNode* node = stack->cursor18;
  TUnit* unit = (node != nullptr) ? node->unit : nullptr;
  while (unit != nullptr) {
    unit->SetOrders(kUnitOrderIdle, -1);
    if (unit->tileIndex06 != stack->tileIndex10) {
      unit->MoveTo(stack->tileIndex10);
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
}

// Not ground truth's own function -- ground truth repeats this exact eligibility check
// inline 4 times inside UpdateDualLinkedEntryMetersAndBlinkState; factored out here rather
// than duplicated.
static bool IsUnitMeterEligible(TUnit* unit) {
  TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
  return milUnit->strength34 > milUnit->strengthSnapshot3C / 2 &&
         (milUnit->battleStateFlags3A & 2) == 0;
}

// FUNCTION: IMPERIALISM 0x004a3830
bool TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState(TArmyStack* stack1, TArmyStack* stack2) {
  // Phase 1: snapshot stack1's units' strength34 into strengthSnapshot3C and clear blink-mask bits 1/2,
  // stopping early the first time a unit's fort-level attacker-penalty lookup is 0.
  TUnit* unit = stack1->ResetCursorAndGetHeadUnit();
  while (unit != nullptr) {
    stack1->fortLevelAttackerPenaltyCache9 = static_cast<unsigned char>(
        g_anFortLevelAttackerPenaltyPercentByLevel
            [g_pGlobalMapState->cityScoreTable[unit->tileIndex06].fortLevel03]);
    if (stack1->fortLevelAttackerPenaltyCache9 == 0) {
      break;
    }
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    milUnit->strengthSnapshot3C = milUnit->strength34;
    milUnit->SetOrClearBattleStateFlags(1, false);
    milUnit->SetOrClearBattleStateFlags(2, false);
    unit = stack1->AdvanceCursorAndGetUnit();
  }

  // Phase 2: same for stack2, except blink-mask bit 1 is set from the unit's
  // blink-eligibility flag rather than always cleared.
  unit = stack2->ResetCursorAndGetHeadUnit();
  while (unit != nullptr) {
    stack2->fortLevelAttackerPenaltyCache9 = static_cast<unsigned char>(
        g_anFortLevelAttackerPenaltyPercentByLevel
            [g_pGlobalMapState->cityScoreTable[unit->tileIndex06].fortLevel03]);
    if (stack2->fortLevelAttackerPenaltyCache9 == 0) {
      break;
    }
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    milUnit->strengthSnapshot3C = milUnit->strength34;
    bool blinkFlag = g_abUnitTypeBlinkEligibilityFlag[unit->orderType] != 0;
    milUnit->SetOrClearBattleStateFlags(1, blinkFlag);
    milUnit->SetOrClearBattleStateFlags(2, false);
    unit = stack2->AdvanceCursorAndGetUnit();
  }

  // Phase 3: repeatedly find one eligible unit per stack (strength34 still above half its
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
void TArmyMgr::DoOwnershipChanges() {
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
      bool eligible = g_pSimMgr->IsNationSlotEligibleForEventProcessing(cachedOwner) != 0;
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
    signed char secondaryOwner =
        g_pGlobalMapState->cityScoreTable[tileIndex].formerOwnerNationCode01;
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
}

// FUNCTION: IMPERIALISM 0x004a3d90
void TArmyMgr::DispatchTileActionByKind(int contextArg, short actionKind) {
  if (actionKind == 1 || actionKind == 4) {
    this->SelectMovableUnitOnCurrentTileAndPlaySfx(contextArg);
  } else if (actionKind == 7) {
    this->CommitCityActionGateCostIfAffordable(contextArg);
  }

  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 4) {
      unit->SetOrders(kUnitOrderIdle, -1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a3e50
bool TArmyMgr::SelectMovableUnitOnCurrentTileAndPlaySfx(int contextArg) {
  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  bool foundMovableUnit = false;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      unit->SetOrders(kUnitOrderRedeploy, contextArg);
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
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      totalCost += unit->GetArmsCarried();
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
  // CString::Format("%d", ...) rather than TSimMgr::NumToCurrency).
  CString currentAmountString;
  currentAmountString.Format("%d", nation->field900);
  CString costString;
  costString.Format("%d", totalCost);
  CString templateText;
  g_pSimMgr->GetString(0x2745, 0, &templateText);
  CString formattedMessage;
  scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(currentAmountString), static_cast<LPCSTR>(costString));
  g_pViewMgr->ModalMessage(formattedMessage, g_ptArmyOrderModalMessage, 2, 0);
  return false;
}

// FUNCTION: IMPERIALISM 0x004a41d0
int TArmyMgr::ComputeSelectedTileCityActionGateSum() {
  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  int totalCost = 0;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      totalCost += unit->GetArmsCarried();
    }
  }
  return totalCost;
}

// FUNCTION: IMPERIALISM 0x004a4260
void TArmyMgr::SetOrdersForIdleUnitsOnPendingTile(int mode) {
  TMilitaryUnit* unit = nullptr;
  if (this->pendingMapActionIndex >= 0 && this->pendingMapActionIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex].stationedUnitChain98;
  }
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0) {
      unit->SetOrders(static_cast<UnitOrder>(mode), -1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a43f0
short TArmyMgr::ActivateFirstIdleTacticalUnitByCategoryAtTile(short categoryId, short tileIndex) {
  TMilitaryUnit* unit = nullptr;
  if (tileIndex >= 0 && tileIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
  }

  bool activatedUnit = false;
  short remainingIdleCount = 0;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->orderType] == categoryId && unit->unitOrder == 0) {
      if (activatedUnit) {
        ++remainingIdleCount;
      } else {
        unit->SetOrders(static_cast<UnitOrder>(4), -1);
        activatedUnit = true;
      }
    }
  }
  return remainingIdleCount;
}

// FUNCTION: IMPERIALISM 0x004a4490
short TArmyMgr::ActivateFirstActiveTacticalUnitByCategoryAtTile(short categoryId, short tileIndex) {
  TMilitaryUnit* unit = nullptr;
  if (tileIndex >= 0 && tileIndex < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain98;
  }

  bool deactivatedUnit = false;
  short idleCount = 0;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->orderType] != categoryId) {
      continue;
    }
    if (unit->unitOrder == 0) {
      ++idleCount;
    } else if ((unit->unitOrder == 2 || unit->unitOrder == 4 || unit->unitOrder == 3) &&
               !deactivatedUnit) {
      unit->SetOrders(kUnitOrderIdle, -1);
      deactivatedUnit = true;
      ++idleCount;
    }
  }
  return idleCount;
}

// FUNCTION: IMPERIALISM 0x004a4550
bool TArmyMgr::HasEligibleStationedUnitInRegion(short regionId) {
  if (regionId == -1) {
    return false;
  }
  TMilitaryUnit* unit = nullptr;
  if (regionId >= 0 && regionId < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain98;
  }
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004a45e0
void TArmyMgr::SetActiveProvinceSelection(short cityRecordIndex) {
  this->pendingMapActionIndex = cityRecordIndex;
  if (cityRecordIndex != -1) {
    TMilitaryUnit* unit;
    if (cityRecordIndex >= 0 && cityRecordIndex < 0x180) {
      unit = g_pGlobalMapState->cityScoreTable[cityRecordIndex].stationedUnitChain98;
    } else {
      unit = nullptr;
    }
    for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
      int orderState = unit->unitOrder;
      if ((static_cast<short>(orderState) == 4 || static_cast<short>(orderState) == 3) &&
          g_awTacticalUnitCategoryCodeBySlot[unit->orderType] != 0) {
        unit->SetOrders(kUnitOrderIdle, -1);
      }
    }
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    static_cast<TArmyToolbar*>(mapView->categoryPages[mapView->activeUnitCategoryIndex96])
        ->SetProvince(cityRecordIndex);
  }
  g_pViewMgr->mapUberPictureF0->InvalidateMap();
}

// FUNCTION: IMPERIALISM 0x004a46d0
void TArmyMgr::ClearProvinceSelectionHighlightsForNation(short nationId) {
  TSortedList* unitList = g_apNationStates[nationId]->militaryUnitList44;
  for (short ordinal = 1; ordinal <= unitList->GetCount(); ++ordinal) {
    TUnit* unit = static_cast<TUnit*>(unitList->GetEntryByOrdinal(ordinal));
    if (unit->unitOrder == 3) {
      unit->SetOrders(kUnitOrderIdle, -1);
    }
  }
  this->pendingMapActionIndex = -1;
}

// FUNCTION: IMPERIALISM 0x004a4760
short TArmyMgr::FindNextSelectableProvinceForNation(short nationId) {
  short candidate = this->pendingMapActionIndex;
  if (candidate == -1) {
    candidate = 0;
  }

  while (candidate < 0x180) {
    const Province& cityRecord = g_pGlobalMapState->cityScoreTable[candidate];
    short ownerNation = cityRecord.ownerNationCode00;
    bool ownerPermitsSelection = false;
    if (ownerNation > -1) {
      ownerPermitsSelection =
          ownerNation == nationId ||
          g_apTerrainTypeDescriptorTable[ownerNation]->IsEncodedNationSlotMinus200Equal(nationId);
    }

    if (ownerPermitsSelection) {
      TMilitaryUnit* unit = cityRecord.stationedUnitChain98;
      while (unit != nullptr) {
        if (unit->unitOrder == 0 &&
            unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
          return candidate;
        }
        unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14);
      }
    }
    ++candidate;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x004a4870
bool TArmyMgr::HandleMapClickByComputedCursorState(short tileIndex, short mode) {
  bool handled = false;
  int cursorState = ComputeMapCursorStateIndex(tileIndex, mode);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  switch (cursorState) {
  case 2:
    if (g_pViewMgr->mapUberPictureF0 != nullptr) {
      g_pViewMgr->mapUberPictureF0->SetMapInteractionMode(1);
      this->SetActiveProvinceSelection(cityRecordIndex);
      handled = true;
    }
    break;
  case 6:
    this->MarchSelectedArmies(tileIndex);
    return true;
  case 8:
    this->ShowSpyReport(cityRecordIndex);
    return true;
  }
  return handled;
}

// FUNCTION: IMPERIALISM 0x004a4930
unsigned short TArmyMgr::LookupMapCursorTokenByStateIndex(short tileIndex, short mode) {
  return g_mapCursorTokenByStateIndex_00695668[ComputeMapCursorStateIndex(tileIndex, mode)];
}

// FUNCTION: IMPERIALISM 0x004a4960
static int __stdcall ComputeMapCursorStateIndex(short tileIndex, short mode) {
  TTerrainStateRecord* rec = &g_pGlobalMapState->terrainStateTable[tileIndex];
  if (rec->perTileVisitedFlag0f > 0) {
    return 6;
  }
  if (mode != 2) {
    if (g_pViewMgr->mapUberPictureF0->HasActiveMapInteractionSelection() != 0) {
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
  if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(activeNationId) == 0) {
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

// FUNCTION: IMPERIALISM 0x004a4aa0
unsigned short TArmyMgr::LookupCivilianMapCursorTokenByStateIndex(short tileIndex, short mode) {
  return g_civilianMapCursorTokenByStateIndex_00695680[this->ComputeCivilianMapCursorStateIndex(
      tileIndex, mode)];
}

// FUNCTION: IMPERIALISM 0x004a4ad0
bool TArmyMgr::HandleMapClickByCivilianCursorState(short tileIndex, short mode) {
  int cursorState = this->ComputeCivilianMapCursorStateIndex(tileIndex, mode);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  switch (cursorState) {
  case 2:
    this->SetActiveProvinceSelection(cityRecordIndex);
    return false;
  case 3:
  case 4:
    break;
  case 5:
    return this->ValidateOrderPlacementPrerequisitesForSelectedTile(cityRecordIndex);
  case 6:
    this->MarchSelectedArmies(tileIndex);
    return false;
  case 7:
    g_pViewMgr->HandleTurnEventDialogFactorySlotEC(this->pendingMapActionIndex);
    return false;
  case 8:
    this->ShowSpyReport(cityRecordIndex);
    // fall through
  default:
    return false;
  }

  const Province& selectedTile = g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex];
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

  TTerrainStateRecord* rec = &g_pGlobalMapState->terrainStateTable[tileIndex];
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
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
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

// Route a map action for the region named by contextArg's low short: walk the pending
// province's adjacent-record list, and if that region is one of them select the movable
// unit on the current tile, otherwise charge the city-action gate cost.
// FUNCTION: IMPERIALISM 0x004a4fc0
void TArmyMgr::DispatchMapActionForRegionByAdjacency(int contextArg) {
  bool isAdjacent = false;
  short index = 0;
  Province* province = &g_pGlobalMapState->cityScoreTable[this->pendingMapActionIndex];
  short adjacentCount = province->adjacentRegionCount08;
  if (0 < adjacentCount) {
    do {
      if (isAdjacent) {
        break;
      }
      if (province->adjacentRegionIds0A[index] == static_cast<short>(contextArg)) {
        isAdjacent = true;
      }
      index = index + 1;
    } while (index < adjacentCount);
  }
  if (!isAdjacent) {
    CommitCityActionGateCostIfAffordable(contextArg);
    return;
  }
  SelectMovableUnitOnCurrentTileAndPlaySfx(contextArg);
}

// FUNCTION: IMPERIALISM 0x004a5080
bool TArmyMgr::ValidateOrderPlacementPrerequisitesForSelectedTile(short cityRecordIndex) {
  TMilitaryUnit* unit = g_pGlobalMapState->GetMilitaryMaster(this->pendingMapActionIndex);
  int totalCost = 0;
  for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      totalCost += unit->GetArmsCarried();
    }
  }
  if (totalCost == 0) {
    return false;
  }

  if (!g_pGlobalMapState->TileHasMovementClassId(this->pendingMapActionIndex, cityRecordIndex)) {
    CString notAdjacentBody;
    CString notAdjacentTitle;
    g_pSimMgr->GetString(0x2745, 4, &notAdjacentBody);
    g_pSimMgr->GetString(0x2745, 5, &notAdjacentTitle);
    g_pViewMgr->ModalMessage(5, notAdjacentTitle, notAdjacentBody, g_ptArmyValidationModalMessage,
                             1, 0);
    return false;
  }

  if (!g_pGlobalMapState->HasPortInProvince(this->pendingMapActionIndex)) {
    CString atWarBody;
    CString atWarTitle;
    g_pSimMgr->GetString(0x2745, 6, &atWarBody);
    g_pSimMgr->GetString(0x2745, 7, &atWarTitle);
    g_pViewMgr->ModalMessage(5, atWarTitle, atWarBody, g_ptArmyValidationModalMessage, 1, 0);
    return false;
  }

  short activeNationId = g_pSimMgr->GetActiveNationId();
  TCountry* activeCountry = g_apTerrainTypeDescriptorTable[activeNationId];
  int reinforcementCost = 0;
  CIterator orderIter(activeCountry->militaryUnitList44);
  for (TUnit* order = static_cast<TUnit*>(orderIter.Reset()); orderIter.More();
       order = static_cast<TUnit*>(orderIter.Advance())) {
    if (order->unitOrder == 1 && order->orderTargetIndex0C == cityRecordIndex &&
        !g_pGlobalMapState->TileHasMovementClassId(order->tileIndex06, cityRecordIndex)) {
      reinforcementCost += static_cast<TMilitaryUnit*>(order)->GetArmsCarried();
    }
  }

  int seaValue = g_pNavyOrderManager->GetInvasionCapacity(
      activeNationId, &g_pGlobalMapState->cityScoreTable[cityRecordIndex], 0);
  if (totalCost + reinforcementCost > seaValue) {
    CString capacityMessage;
    CString capacityTemplate;
    CString seaValueText;
    CString totalCostText;
    CString reinforcementText;
    if (reinforcementCost == 0) {
      g_pSimMgr->GetString(0x2745, 1, &capacityTemplate);
      seaValueText.Format(g_szDecimalFormat, seaValue);
      totalCostText.Format(g_szDecimalFormat, totalCost);
      scanBracketExpressions(g_pSimMgr, &capacityMessage, static_cast<LPCSTR>(capacityTemplate),
                             static_cast<LPCSTR>(seaValueText), static_cast<LPCSTR>(totalCostText));
    } else {
      g_pSimMgr->GetString(0x2745, 2, &capacityTemplate);
      seaValueText.Format(g_szDecimalFormat, seaValue);
      reinforcementText.Format(g_szDecimalFormat, reinforcementCost);
      totalCostText.Format(g_szDecimalFormat, totalCost);
      scanBracketExpressions(g_pSimMgr, &capacityMessage, static_cast<LPCSTR>(capacityTemplate),
                             static_cast<LPCSTR>(seaValueText),
                             static_cast<LPCSTR>(reinforcementText),
                             static_cast<LPCSTR>(totalCostText));
    }
    g_pViewMgr->ModalMessage(capacityMessage, g_ptArmyValidationModalMessage, 2, 0);
    return false;
  }

  for (unit = g_pGlobalMapState->GetMilitaryMaster(this->pendingMapActionIndex); unit != nullptr;
       unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      unit->SetOrders(kUnitOrderRedeploy, cityRecordIndex);
    }
  }
  g_pGlobalMapState->MarkAdjacentHexOrderDirectionAndSelectTile(this->pendingMapActionIndex,
                                                                cityRecordIndex, 1);

  if (g_pViewMgr->mapUberPictureF0 != nullptr) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aa7, 0, 1);
    g_pViewMgr->mapUberPictureF0->NoticeTile(
        g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex04);
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x004a5760
void TArmyMgr::MarchSelectedArmies(short tileIndex) {
  short direction = (g_pGlobalMapState->terrainStateTable[tileIndex].perTileVisitedFlag0f - 1) % 6;
  short neighborTile = TMapMgr::GetNeighborTileID(tileIndex, direction);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[neighborTile].cityRecordIndex;

  short activeNationId = g_pSimMgr->GetActiveNationId();
  TGreatPower* nationState = g_apNationStates[activeNationId];
  int categoryCounts[10] = {0};

  // Per-unit "was this order anchored on cityRecordIndex" scratch flags -- one byte per
  // list entry, walked in lockstep with the CIterator below. Original never frees this
  // buffer (no operator_delete in the disassembly); reproduced as-is.
  unsigned char* unitOnTileFlags = new unsigned char[nationState->militaryUnitList44->GetCount()];
  memset(unitOnTileFlags, 0, nationState->militaryUnitList44->GetCount());

  CIterator unitIter(nationState->militaryUnitList44);
  unsigned char* flagCursor = unitOnTileFlags;
  for (TUnit* unit = static_cast<TUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TUnit*>(unitIter.Advance())) {
    if (unit->orderTargetIndex0C == cityRecordIndex) {
      categoryCounts[g_awTacticalUnitCategoryCodeBySlot[unit->orderType]]++;
      *flagCursor = 1;
    }
    ++flagCursor;
  }

  if (!g_pViewMgr->DispatchProvinceOrderOverlayConfirmDialog(cityRecordIndex, categoryCounts)) {
    short activeNationId2 = g_pSimMgr->GetActiveNationId();
    bool sameOwner =
        g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode00 == activeNationId2;

    flagCursor = unitOnTileFlags;
    for (TUnit* unit = static_cast<TUnit*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TUnit*>(unitIter.Advance())) {
      if (*flagCursor != 0) {
        if (sameOwner &&
            !g_pGlobalMapState->TileHasMovementClassId(unit->tileIndex06, cityRecordIndex)) {
          short cost = static_cast<TMilitaryUnit*>(unit)->GetArmsCarried();
          short activeNationId3 = g_pSimMgr->GetActiveNationId();
          g_apNationStates[activeNationId3]->field900 += cost;
        }
        unit->SetOrders(kUnitOrderIdle, -1);
      }
      ++flagCursor;
    }

    short neighborTiles[6];
    TMapMgr::GetNeighborTileIDArray(tileIndex, neighborTiles,
                                    g_pGlobalMapState->hexNeighborWrapHorizontally);
    for (int i = 0; i < 6; ++i) {
      short nt = neighborTiles[i];
      if (nt == -1) {
        continue;
      }
      unsigned char flag = g_pGlobalMapState->terrainStateTable[nt].perTileVisitedFlag0f;
      if (flag == 0) {
        continue;
      }
      if ((flag - 1) % 6 != (i + 3) % 6) {
        continue;
      }
      g_pGlobalMapState->terrainStateTable[nt].perTileVisitedFlag0f = 0;
      if (g_pViewMgr->mapUberPictureF0 != nullptr) {
        g_pViewMgr->mapUberPictureF0->InvalidateTile(nt);
      }
    }

    g_pGlobalMapState->MarkDirectionalMapOverlayFlagsForNationOrders();
    if (this->pendingMapActionIndex != -1) {
      this->SetActiveProvinceSelection(this->pendingMapActionIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a5aa0
int TArmyMgr::ComputeWeightedNeighborLinkScoreForNodeIndex(int nodeIndexArg) {
  short nodeIndex = static_cast<short>(nodeIndexArg);
  TMilitaryUnit* chain;
  if (nodeIndex < 0 || nodeIndex >= 0x180) {
    chain = 0;
  } else {
    chain = static_cast<TMilitaryUnit*>(
        g_pGlobalMapState->cityScoreTable[nodeIndex].stationedUnitChain98);
  }
  int sum = 0;
  for (; chain != 0; chain = static_cast<TMilitaryUnit*>(chain->nextAtLocation14)) {
    sum += g_anWeightedNeighborUnitScoreByType_006955F0[chain->orderType];
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004a5b10
void TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup(TArmyStack* ourStack,
                                                                TArmyStack* enemyStack,
                                                                int ownerNationCodeInt) {
  int compositionClass = g_pGlobalMapState->ClassifyCityGateTerrainComposition(ownerNationCodeInt);
  int fortLevel = g_pGlobalMapState->cityScoreTable[ownerNationCodeInt].fortLevel03;
  if (fortLevel > 0) {
    fortLevel++;
  }

  TArmyBattle* newBattle = new TArmyBattle();
  newBattle->AllocateRecordList();
  newBattle->InitializeBattleSetupAndMaybeDispatchTurnEventED8(
      ourStack, enemyStack, compositionClass, fortLevel, ownerNationCodeInt);

  this->ourStackBattle39c = ourStack;
  this->enemyStackBattle3a0 = enemyStack;
  this->activeBattleView3a4 = newBattle;

  if (g_pSimMgr->multiplayerSessionRole == 1) {
    g_pGameFlowState->NoOpCallbackRet4(newBattle);
  }
  newBattle->StartBattle();
}

// FUNCTION: IMPERIALISM 0x004a5ca0
void TArmyMgr::ApplyPostBattleStackOutcomeAndGrowUnitMeters(TArmyStack* ourStack,
                                                            TArmyStack* enemyStack, int sideWonFlag,
                                                            int battleSiteIndex) {
  BuildArmyContextActionRecordsAndDispatchLabel(ourStack, enemyStack, sideWonFlag, battleSiteIndex,
                                                1);

  if (sideWonFlag != 0) {
    this->RedistributeUnitOrderQueueToRandomAdjacentRegion(enemyStack,
                                                           static_cast<short>(battleSiteIndex));

    // Winning stack: settle every unit into its tile (raw head14/cursor18 walk -- no
    // calls emitted, matching TryCreateTacticalBattleViewForTileArmies's peaceful path).
    TArmyStackUnitNode* node = ourStack->head14;
    ourStack->cursor18 = node;
    TUnit* unit = (node != 0) ? node->unit : 0;
    while (unit != 0) {
      unit->MoveTo(unit->orderTargetIndex0C);
      unit->SetOrders(kUnitOrderIdle, -1);
      node = ourStack->cursor18;
      if (node != 0) {
        node = node->next;
        ourStack->cursor18 = node;
        unit = (node != 0) ? node->unit : 0;
      } else {
        unit = 0;
      }
    }

    this->perTileOwnerNationCodeCache1c[battleSiteIndex] = ourStack->categoryFlag8;

    // Boosted quality growth for the winner (raw walk, duplicates
    // TArmyStack::ApplyMeterGrowthToEligibleUnits(true)'s body inline).
    node = ourStack->head14;
    ourStack->cursor18 = node;
    unit = (node != 0) ? node->unit : 0;
    while (unit != 0) {
      TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
      if (milUnit->strength34 > 0) {
        milUnit->experiencePercent38 = static_cast<short>(milUnit->experiencePercent38 + 0x23);
        if (milUnit->experiencePercent38 > 0x190) {
          milUnit->experiencePercent38 = 0x190;
        }
      }
      node = ourStack->cursor18;
      if (node != 0) {
        node = node->next;
        ourStack->cursor18 = node;
        unit = (node != 0) ? node->unit : 0;
      } else {
        unit = 0;
      }
    }

    // Non-boosted quality growth for the loser (same raw walk, +20 instead of +35).
    node = enemyStack->head14;
    enemyStack->cursor18 = node;
    unit = (node != 0) ? node->unit : 0;
    while (unit != 0) {
      TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
      if (milUnit->strength34 > 0) {
        milUnit->experiencePercent38 = static_cast<short>(milUnit->experiencePercent38 + 0x14);
        if (milUnit->experiencePercent38 > 0x190) {
          milUnit->experiencePercent38 = 0x190;
        }
      }
      node = enemyStack->cursor18;
      if (node != 0) {
        node = node->next;
        enemyStack->cursor18 = node;
        unit = (node != 0) ? node->unit : 0;
      } else {
        unit = 0;
      }
    }

    this->ResolveNextMove();
  } else {
    this->RelocateStackUnitsToStackTile(ourStack);

    // Non-boosted quality growth for the loser (ourStack), via the real accessors --
    // ground truth emits real calls for this walk (only the growth loops above inline).
    for (TUnit* unit = ourStack->ResetCursorAndGetHeadUnit(); unit != 0;
         unit = ourStack->AdvanceCursorAndGetUnit()) {
      TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
      if (milUnit->strength34 > 0) {
        milUnit->experiencePercent38 = static_cast<short>(milUnit->experiencePercent38 + 0x14);
        if (milUnit->experiencePercent38 > 0x190) {
          milUnit->experiencePercent38 = 0x190;
        }
      }
    }

    enemyStack->ApplyMeterGrowthToEligibleUnits(true);
    this->ResolveNextMove();
  }
}

// FUNCTION: IMPERIALISM 0x004a5ec0
bool TArmyMgr::GenerateSpyReport(int cityRecordIndex, CString& outDefenderSummary,
                                 CString& outGarrisonSummary) {
  int bestScore = -1;
  CString candidateName;

  // Phase 1: scan the city's adjacent regions owned by the active nation for the
  // strongest stationed military unit; fall back to the region's own display name when
  // an owned region has none.
  int adjacentRegionCount =
      g_pGlobalMapState->cityScoreTable[cityRecordIndex].adjacentRegionCount08;
  if (adjacentRegionCount > 0) {
    int i = 0;
    do {
      short regionId = g_pGlobalMapState->cityScoreTable[cityRecordIndex].adjacentRegionIds0A[i];
      if (g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(regionId) ==
          g_pSimMgr->GetActiveNationId()) {
        TMilitaryUnit* unit = nullptr;
        if (regionId >= 0 && regionId < 0x180) {
          unit = static_cast<TMilitaryUnit*>(
              g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain98);
        }
        for (; unit != nullptr; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
          if (unit->orderType >= EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1)) {
            int score = static_cast<short>(unit->experiencePercent38 / 100) + 1;
            if (bestScore < score) {
              candidateName = unit->name24;
              outDefenderSummary = candidateName;
              bestScore = score;
            }
          }
        }
        if (bestScore < 0) {
          bestScore = 0;
          g_pGlobalMapState->AssignCityRecordDisplayName(regionId, &candidateName);
          g_pSimMgr->GetString(0x2744, 1, &outDefenderSummary);
          outDefenderSummary =
              CString(outDefenderSummary + s_szSpaceSeparator_00695794 + candidateName);
        }
      }
      ++i;
    } while (i < adjacentRegionCount);
  }

  // Phase 2: separately look for a ship owned by the active nation whose zone covers
  // cityRecordIndex, reducing to the preferred one; its admiral can outrank Phase 1's
  // pick, or (only when Phase 1 found nothing at all) the ship's own name is the
  // fallback.
  TShip* bestShip = nullptr;
  for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
    if (ship->nation == g_pSimMgr->GetActiveNationId() &&
        ship->location->ContainsCityStatePointerInZoneArrayByCityIndex(cityRecordIndex)) {
      bestShip = ship->Finest(bestShip, 0);
    }
  }
  if (bestShip != nullptr) {
    CString selectedName;
    TAdmiral* admiral = bestShip->admiral;
    if (admiral == nullptr) {
      if (bestScore == -1) {
        selectedName = bestShip->name;
        g_pSimMgr->GetString(0x2744, 3, &outDefenderSummary);
        outDefenderSummary += s_szSpaceSeparator_00695794 + selectedName;
        bestScore = 0;
      }
    } else {
      int admiralScore = static_cast<short>(admiral->experiencePoints / 100) + 1;
      if (bestScore < admiralScore) {
        selectedName = CString(s_szAdmiralPrefix_0069578c + admiral->displayName);
        g_pSimMgr->GetString(0x2744, 2, &outDefenderSummary);
        outDefenderSummary += s_szSpaceSeparator_00695794 + selectedName;
        bestScore = admiralScore;
      }
    }
  }

  if (bestScore == -1) {
    return false;
  }

  // Phase 3: tally the city's stationed units into 11 resource buckets via a
  // per-strength-tier weighted roll, seeded from the city/turn/nation. The category
  // result is biased by 3: 4 selects the misc bucket, 5 selects a random bucket, and
  // every other result selects the unit's movement class.
  short activeNationId = g_pSimMgr->GetActiveNationId();
  short turnTick = g_pSimMgr->GetEconomicTurn();
  int seed = cityRecordIndex + turnTick + activeNationId;
  if (seed == 0) {
    seed = cityRecordIndex;
  }

  int resourceBuckets[11];
  memset(resourceBuckets, 0, sizeof(resourceBuckets));
  short citySlot = static_cast<short>(cityRecordIndex);
  TMilitaryUnit* unit = nullptr;
  if (citySlot >= 0 && citySlot < 0x180) {
    unit = static_cast<TMilitaryUnit*>(
        g_pGlobalMapState->cityScoreTable[citySlot].stationedUnitChain98);
  }
  if (unit != nullptr) {
    const short* pointCostWeights = g_MapOrderResourceRollWeightTable_0064c5d8[bestScore];
    const short* categoryWeights = g_MapOrderResourceRollWeightTable_0064c5d8[bestScore] + 3;
    do {
      seed = seed * 0x15a4e35 + 1;
      short pointCost = static_cast<short>(FindCumulativeWeightBucketIndex(
          const_cast<short*>(pointCostWeights),
          static_cast<short>(static_cast<int>(static_cast<unsigned int>(seed) >> 0xc & 0x7fff) %
                             100)));
      seed = seed * 0x15a4e35 + 1;
      short category = static_cast<short>(
          FindCumulativeWeightBucketIndex(
              const_cast<short*>(categoryWeights),
              static_cast<short>(static_cast<int>(static_cast<unsigned int>(seed) >> 0xc & 0x7fff) %
                                 100)) +
          3);
      switch (category) {
      default:
        category = unit->GetCategory();
        break;
      case 5:
        seed = seed * 0x15a4e35 + 1;
        category = static_cast<short>(
            static_cast<int>(static_cast<unsigned int>(seed) >> 0xc & 0x7fff) % 10);
        break;
      case 4:
        category = 10;
        break;
      }
      unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14);
      resourceBuckets[category] += pointCost;
    } while (unit != nullptr);
  }

  // Phase 4: format the non-empty buckets into a comma-separated "<count> <resource>"
  // list (singular/plural string group 0x2726, offset i vs i+11), or a fallback when
  // nothing was garrisoned.
  {
    CString emptySummary(g_szEmptyString);
    outGarrisonSummary = emptySummary;
  }
  CString resourceTypeName;
  CString countText;
  short renderedBucketCount = 0;
  int bucket = 0;
  int* bucketCursor = resourceBuckets;
  do {
    int count = *bucketCursor;
    if (count != 0) {
      if (renderedBucketCount != 0) {
        outGarrisonSummary += g_szListSeparator_00695760;
      }
      g_pSimMgr->GetString(0x2726, static_cast<short>(count == 1 ? bucket : bucket + 0xb),
                           &resourceTypeName);
      countText.Format(g_szDecimalFormat, count);
      outGarrisonSummary += countText + s_szSpaceSeparator_00695794 + resourceTypeName;
      ++renderedBucketCount;
    }
    ++bucket;
    ++bucketCursor;
  } while (bucket < 0xb);
  if (renderedBucketCount == 0) {
    g_pSimMgr->GetString(0x2744, 9, &outGarrisonSummary);
  }
  outGarrisonSummary += ".";

  return true;
}

// FUNCTION: IMPERIALISM 0x004a6680
void TArmyMgr::ShowSpyReport(int cityRecordIndex) {
  TextStyle styleA;
  InitializeUiTextStyleDescriptor(&styleA, 0, 0xe, 0x2b67, 1);

  TextStyle styleB;
  BuildUiTextStyleDescriptor(&styleB, 0, 0xc, 0x2b67);

  TextStyle styleC;
  InitializeUiTextStyleDescriptor(&styleC, 0, 0xa, 0x2b67, 3);

  TextStyle styleD;
  InitializeUiTextStyleDescriptor(&styleD, 2, 0xa, 0x2b67, 3);

  CString defenderSummary;
  CString garrisonSummary;
  if (!this->GenerateSpyReport(cityRecordIndex, defenderSummary, garrisonSummary)) {
    CString noSummaryMessage;
    g_pSimMgr->GetString(0x2744, 8, &noSummaryMessage);
    g_pViewMgr->ModalMessage(noSummaryMessage, g_ptArmyValidationModalMessage, 1, 0);
    return;
  }

  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventEnemyFleetReport));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyMgr_0069573C, 0xa4d);
  }
  node->SetModality(1);

  // MapView.rsrc view 9475's children, in the order the original fills them.
  CString scratchText;
  TStaticText* ownerLabel =
      static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagGpee)); // 'gpee'
  ownerLabel->AssertValid();
  g_apTerrainTypeDescriptorTable[g_pGlobalMapState->cityScoreTable[cityRecordIndex]
                                     .ownerNationCode00]
      ->FormatOverlayTerrainLabelText(&scratchText);
  ownerLabel->SetTextAndMaybeRefresh(&scratchText, 0);
  ownerLabel->InstallTextStyle(styleB, 0);

  TStaticText* zoneLabel =
      static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagZone)); // 'zone'
  zoneLabel->AssertValid();
  CString cityDisplayName;
  g_pGlobalMapState->AssignCityRecordDisplayName(static_cast<ProvinceIndex>(cityRecordIndex),
                                                 &cityDisplayName);
  scratchText = cityDisplayName;
  zoneLabel->SetTextAndMaybeRefresh(&scratchText, 0);
  zoneLabel->InstallTextStyle(styleB, 0);

  TStaticText* defenderLabel =
      static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagAdam)); // 'adam'
  defenderLabel->AssertValid();
  defenderLabel->SetTextAndMaybeRefresh(&defenderSummary, 0);
  defenderLabel->InstallTextStyle(styleC, 0);

  TStaticText* garrisonLabel =
      static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagShip)); // 'ship'
  garrisonLabel->AssertValid();
  CString quotedGarrison = CString(g_szDoubleQuote) + garrisonSummary + g_szDoubleQuote;
  garrisonLabel->SetTextAndMaybeRefresh(&quotedGarrison, 0);
  garrisonLabel->InstallTextStyle(styleC, 0);

  TStaticText* titleLabel =
      static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagTitl)); // 'titl'
  titleLabel->AssertValid();
  titleLabel->SetTextFromStringResource(0x2744, 5, 0);
  titleLabel->InstallTextStyle(styleA, 0);

  TStaticText* label1 = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagLab1));
  label1->AssertValid();
  label1->SetTextFromStringResource(0x2744, 6, 0);
  label1->InstallTextStyle(styleC, 0);

  TStaticText* label2 = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagLab2));
  label2->AssertValid();
  label2->SetTextFromStringResource(0x2744, 7, 0);
  label2->InstallTextStyle(styleC, 0);

  TStaticText* label3 = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagLab3));
  label3->AssertValid();
  label3->SetEnabled(0, 0);
  label3->InstallTextStyle(styleB, 0);

  TStaticText* label4 = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagLab4));
  label4->AssertValid();
  label4->SetTextFromStringResource(0x2744, 8, 0);
  label4->InstallTextStyle(styleD, 0);

  TDialogBehavior* behavior = node->GetDialogBehavior();
  if (behavior != nullptr) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x004a6d40
bool TArmyMgr::ScanMapContextActionEntriesForCodeMatch(short activeNationId) {
  int remaining = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
  if (remaining <= 0) {
    return false;
  }
  do {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
            remaining));
    if (activeNationId == static_cast<signed char>(record->nationIds[0]) ||
        activeNationId == static_cast<signed char>(record->nationIds[1])) {
      return true;
    }
    if (g_bRandomMapDeveloperCheatFlag) {
      return true;
    }
    --remaining;
  } while (remaining > 0);
  return false;
}

// FUNCTION: IMPERIALISM 0x004a6dd0
unsigned char TArmyMgr::GetByteFlagAtOffset8() {
  return flag8;
}

// FUNCTION: IMPERIALISM 0x004a6df0
void TArmyMgr::CleanUpStacks() {
  if (mapContextActionRecordList04 != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList04->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList04->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords250[0];
      delete[] record->sideChildRecords250[1];
      record->sideChildRecords250[1] = 0;
      record->sideChildRecords250[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList04->ClearAndFreeAllPtrListRecords();
  }
  flag8 = 0;
}

// FUNCTION: IMPERIALISM 0x004a6e80
void TArmyMgr::AppendMapContextActionRecordAndResetWorkingFields(MapOrderBattleSnapshot* record,
                                                                 int unusedArg2) {
  (void)unusedArg2;
  mapContextActionRecordList04->AppendCopiedRecordToPtrList(record);
  record->childRecords[1] = nullptr; // +0x254
  record->childRecords[0] = nullptr; // +0x250
  record->childCount[1] = 0;         // +0x24c
  record->childCount[0] = 0;         // +0x24a
  flag8 = 1;
  // Redundant re-store (both branches write the same 1); preserved to match codegen.
  if (g_bRandomMapDeveloperCheatFlag != 0) {
    flag8 = 1;
  }
}

// FUNCTION: IMPERIALISM 0x004a6ef0
void TArmyMgr::TrimExcessNavyOrderSupportAndRebuildOrderBuffer(char nationId, int cityIndex,
                                                               MapOrderBattleSnapshot* snapshot) {
  // nationId carries TTaskForce::nation, which every navy-order reader
  // treats as the entry's owning nation slot (RemoveMatchingTaskForceOrders above) --
  // used below as a g_apNationStates index. `side` is recovered implicitly by comparing
  // this byte against snapshot->nationIds[0]: side 0's own call always matches
  // trivially (side = 0); side 1's call only diverges -- and only then runs the trim --
  // when the two sides' nation slots differ.
  int side = (nationId != snapshot->nationIds[0]) ? 1 : 0;

  TList* scratchList = new TList();

  int budget = 0;
  TCountry* nation = g_apNationStates[static_cast<int>(nationId)];
  CIterator unitIter(nation->militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    if (unit->orderTargetIndex0C == cityIndex &&
        !g_pGlobalMapState->TileHasMovementClassId(unit->tileIndex06, cityIndex)) {
      scratchList->AddTail(unit);
      budget += unit->GetArmsCarried();
    }
  }

  budget -= g_pNavyOrderManager->GetInvasionCapacity(
      nationId, &g_pGlobalMapState->cityScoreTable[cityIndex], 0);

  if (budget > 0) {
    int evictedCount = 0;
    do {
      if (scratchList->GetCount() == 0) {
        break;
      }
      int ordinal = rand() % scratchList->GetCount() + 1;
      TMilitaryUnit* evicted = static_cast<TMilitaryUnit*>(scratchList->GetEntryByOrdinal(ordinal));
      POSITION pos = scratchList->listState.Find(evicted);
      if (pos != nullptr) {
        scratchList->listState.RemoveAt(pos);
      }
      budget -= evicted->GetArmsCarried();
      ++evictedCount;
      evicted->strength34 = static_cast<short>(0xffaa);
    } while (budget > 0);

    int oldCount = snapshot->childCount[side];
    MapOrderBattleSideChildRecord* oldRecords = snapshot->childRecords[side];
    int newCount = oldCount + evictedCount;
    snapshot->childCount[side] = static_cast<short>(newCount);

    // Original never frees oldRecords here -- reproduced as-is (see the analogous
    // acknowledged leak elsewhere in this file).
    MapOrderBattleSideChildRecord* newRecords = nullptr;
    if (newCount > 0) {
      newRecords = new MapOrderBattleSideChildRecord[newCount];
    }
    snapshot->childRecords[side] = newRecords;
    memcpy(newRecords, oldRecords, oldCount * sizeof(MapOrderBattleSideChildRecord));

    if (evictedCount != 0) {
      int recordIndex = oldCount;
      for (int pass = 0; pass < evictedCount; ++pass) {
        CIterator evictedIter(nation->militaryUnitList44);
        for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(evictedIter.Reset());
             evictedIter.More(); unit = static_cast<TMilitaryUnit*>(evictedIter.Advance())) {
          if (unit->strength34 == static_cast<short>(0xffaa)) {
            unit->strength34 = 0;
            MapOrderBattleSideChildRecord& rec = newRecords[recordIndex];
            ++recordIndex;
            rec.resourceType = unit->orderType;
            rec.stockOrRequired = static_cast<short>(0xffaa);
            rec.nameBuffer[0] = 0;
            CString unitName = unit->name24;
            LPCSTR unitNameChars = static_cast<LPCSTR>(unitName);
            for (int c = 0; c < 0x20; ++c) {
              char ch = unitNameChars[c];
              rec.nameBuffer[c] = ch;
              if (ch == '\0') {
                break;
              }
            }
            // Final battle-report row category; the working unit pointer is no longer
            // needed once the evicted unit has been copied into the record.
            rec.detailIdentity.categoryTag = kControlTagArmy; // 'army'
            rec.strengthBucket = static_cast<short>(unit->experiencePercent38 / 100);
            unit->DetachUnitOrderFromOwnerAndReset();
            unit->Free();
          }
        }
      }
    }
  }

  scratchList->RemoveAll();
  scratchList->Free();
}

// FUNCTION: IMPERIALISM 0x004a7370
void ValidateOrderSupportDeltaAndMarkDirectionalOverlays(int nationSlot, short zone) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  int totalArms = 0;
  CIterator cursor(nation->militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset()); cursor.More();
       unit = static_cast<TMilitaryUnit*>(cursor.Advance())) {
    if (unit->orderTargetIndex0C == zone) {
      if (g_pGlobalMapState->TileHasMovementClassId(unit->tileIndex06, zone) == 0) {
        totalArms += unit->GetArmsCarried();
      }
    }
  }
  short capacity = g_pNavyOrderManager->GetInvasionCapacity(
      static_cast<short>(nationSlot), &g_pGlobalMapState->cityScoreTable[zone], 0);
  if (totalArms != capacity && totalArms - capacity > -1) {
    CString message;
    g_pSimMgr->GetString(0x2745, 10, &message);
    g_pViewMgr->ModalMessage(message, g_ptArmyValidationModalMessage);
    g_pGlobalMapState->MarkDirectionalMapOverlayFlagsForNationOrders();
  }
}

// FUNCTION: IMPERIALISM 0x004a7590
void TArmyMgr::ClearNationArmyActionModesAndCycleSelection(int nationId) {
  TLongintList* regionList = g_apNationStates[nationId]->ownedRegionList;
  POSITION position = regionList->GetHeadPosition();
  while (position != NULL) {
    short cityIndex = static_cast<short>(regionList->GetNext(position));
    TMilitaryUnit* unit = g_pGlobalMapState->GetMilitaryMaster(cityIndex);
    while (unit != 0) {
      if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia) &&
          unit->unitOrder != 1) {
        unit->SetOrders(kUnitOrderIdle, -1);
      }
      unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14);
    }
  }

  TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
  if (mapView != 0 && !mapView->HasActiveMapInteractionSelection()) {
    mapView->CycleMapInteractionSelectionAfterHandledClick();
  }
}
