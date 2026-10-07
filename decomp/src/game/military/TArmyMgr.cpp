#include "game/military/TArmyMgr.h"
#include "game/military/TArmyStackList.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TWindow.h"
#include "game/assets/TAssetMgr.h"
#include "game/TEvent.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"

#include <stdlib.h>
#include <mbstring.h>
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
#include "game/military/mapped_flavor_text.h"
#include "game/navy_order.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004a13c0
void MapContextActionRecord::ReadFrom(TStream* stream) {
  stream->ReadBytes(&reportParticipantIndex, 1);
  stream->ReadBytes(&displayedParticipantIndex, 1);
  stream->ReadBytes(&reportKind, 4);
  short nodeId;
  stream->ReadBytes(&nodeId, 2);
  if (reportKind == kMapContextReportLandBattle ||
      reportKind == kMapContextReportPreemptedLandBattle ||
      reportKind == kMapContextReportUncontestedTakeover) {
    location = reinterpret_cast<void*>(static_cast<int>(nodeId));
  } else {
    location = FindMapActionContextByNodeId(nodeId);
  }

  for (int side = 0; side < 2; ++side) {
    stream->ReadBytes(&nationIds[side], 1);
    if (g_nSaveFormatVersion < 0x2c) {
      stream->ReadString(nameBuffer[side].data, 32);
      stream->ReadString(overlayLabel[side].data, 255);
    } else {
      stream->ReadBytes(nameBuffer[side].data, 32);
      stream->ReadBytes(overlayLabel[side].data, 255);
    }
    stream->ReadBytes(&childCount[side], 2);

    delete[] sideChildRecords[side];
    short count = childCount[side];
    MapOrderBattleSideChildRecord* newArray = new MapOrderBattleSideChildRecord[count];
    sideChildRecords[side] = newArray;

    for (int j = 0; j < childCount[side]; ++j) {
      MapOrderBattleSideChildRecord& elem = sideChildRecords[side][j];
      stream->ReadBytes(&elem.resourceType, 2);
      stream->ReadBytes(&elem.stockOrRequired, 2);
      if (g_nSaveFormatVersion < 0x2c) {
        stream->ReadString(&elem.nameBuffer, 32);
      } else {
        stream->ReadBytes(&elem.nameBuffer, 32);
      }
      stream->ReadBytes(&elem.strengthBucket, 2);
      stream->ReadBytes(&elem.detailIdentity, 4);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a1640
void MapContextActionRecord::WriteTo(TStream* stream) {
  stream->WriteBytes(&reportParticipantIndex, 1);
  stream->WriteBytes(&displayedParticipantIndex, 1);
  stream->WriteBytes(&reportKind, 4);

  short nodeId;
  if (reportKind == kMapContextReportLandBattle ||
      reportKind == kMapContextReportPreemptedLandBattle ||
      reportKind == kMapContextReportUncontestedTakeover) {
    nodeId = static_cast<short>(reinterpret_cast<int>(location));
  } else {
    nodeId = static_cast<TZone*>(location)->GetContextOrdinalOrInvalid();
  }
  stream->WriteBytes(&nodeId, 2);

  for (int side = 0; side < 2; ++side) {
    stream->WriteBytes(&nationIds[side], 1);
    stream->WriteBytes(nameBuffer[side].data, 32);
    stream->WriteBytes(overlayLabel[side].data, 255);
    stream->WriteBytes(&childCount[side], 2);
    for (int i = 0; i < childCount[side]; ++i) {
      MapOrderBattleSideChildRecord& child = sideChildRecords[side][i];
      stream->WriteBytes(&child.resourceType, 2);
      stream->WriteBytes(&child.stockOrRequired, 2);
      stream->WriteBytes(child.nameBuffer, 32);
      stream->WriteBytes(&child.strengthBucket, 2);
      stream->WriteBytes(&child.detailIdentity, 4);
    }
  }
}

IMPLEMENT_DYNCREATE(TArmyMgr, TObject)

static int __stdcall ComputeMapCursorStateIndex(short tileIndex, short mode);

// FUNCTION: IMPERIALISM 0x004a1870
TArmyMgr::TArmyMgr() {
  pendingMapActionIndex = -1;
  mapContextActionRecordList = 0;
}

// FUNCTION: IMPERIALISM 0x004a18d0
TArmyMgr::~TArmyMgr() {}

// FUNCTION: IMPERIALISM 0x004a18f0
void TArmyMgr::IArmyMgr() {
  pendingUnitPool = new TArmyStackList();
  staticTable14 = g_MapContextStaticTable_00695448;
  staticTable18 = g_MapContextStaticTable_00695428;
  needsTerrainRefreshFlag = false;
  ourStackBattle = 0;
  enemyStackBattle = 0;
  activeBattleView = 0;
  mapContextActionRecordList = new TSortedPtrList();
  mapContextActionRecordList->recordSize = sizeof(MapContextActionRecord);
  battlesToReport = false;
}

// FUNCTION: IMPERIALISM 0x004a1a00
void TArmyMgr::Free() {
  if (pendingUnitPool != 0) {
    pendingUnitPool->FreeList();
  }
  pendingUnitPool = 0;

  if (mapContextActionRecordList != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords[0];
      delete[] record->sideChildRecords[1];
      record->sideChildRecords[1] = 0;
      record->sideChildRecords[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList->DeleteAll();
  }
  battlesToReport = false;

  if (mapContextActionRecordList != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords[0];
      delete[] record->sideChildRecords[1];
      record->sideChildRecords[1] = 0;
      record->sideChildRecords[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList->FreeList();
  }

  if (ourStackBattle != 0) {
    ourStackBattle->Free();
  }
  ourStackBattle = 0;
  if (enemyStackBattle != 0) {
    enemyStackBattle->Free();
  }
  enemyStackBattle = 0;
  if (activeBattleView != 0) {
    activeBattleView->Free();
  }
  activeBattleView = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x004a1b80
void TArmyMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  if (mapContextActionRecordList != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords[0];
      delete[] record->sideChildRecords[1];
      record->sideChildRecords[1] = 0;
      record->sideChildRecords[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList->DeleteAll();
  }
  battlesToReport = false;
  if (g_nSaveFormatVersion >= 0x25) {
    int count = stream->ReadInteger();
    while (count-- != 0) {
      MapContextActionRecord record;
      record.childCount[1] = 0;
      record.childCount[0] = 0;
      record.sideChildRecords[1] = 0;
      record.sideChildRecords[0] = 0;

      record.ReadFrom(stream);
      mapContextActionRecordList->AppendCopiedRecordToPtrList(&record);
      battlesToReport = true;

      record.sideChildRecords[1] = 0;
      record.sideChildRecords[0] = 0;
      record.childCount[1] = 0;
      record.childCount[0] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a1dd0
void TArmyMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  int count = mapContextActionRecordList->GetSize();
  stream->WriteInteger(count);
  for (int index = 0; index < mapContextActionRecordList->GetSize(); ++index) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(index + 1));
    record->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x004a1e40
void TArmyMgr::DoCombatMoves() {
  bool isNetworkClient = (g_pSimMgr->multiplayerSessionRole == kSessionRoleClient);
  if (isNetworkClient) {
    ClearPendingStacksAndFinalizeMilitaryUnits();
    g_pSimMgr->StartNextPhase();
  } else {
    FormStacks();
    nextStackOrdinal = 1;
    ResolveNextMove();
  }
}

// FUNCTION: IMPERIALISM 0x004a1eb0
void TArmyMgr::EndBattlePhase() {
  if (ourStackBattle != NULL) {
    ourStackBattle->Free();
  }
  ourStackBattle = NULL;
  if (enemyStackBattle != NULL) {
    enemyStackBattle->Free();
  }
  enemyStackBattle = NULL;
  if (activeBattleView != NULL) {
    activeBattleView->Free();
  }
  activeBattleView = NULL;

  ClearPendingStacksAndFinalizeMilitaryUnits();
  DoOwnershipChanges();

  if (needsTerrainRefreshFlag) {
    g_pMacViewMgr->RegenerateCountryRegions();
    for (int i = 0; i < kTerrainTypeDescriptorTableCount; ++i) {
      if (g_apTerrainTypeDescriptorTable[i] != NULL) {
        g_apTerrainTypeDescriptorTable[i]->SetCenterTile(-1);
      }
    }
  }
  needsTerrainRefreshFlag = false;
  g_pSimMgr->StartNextPhase();
}

// FUNCTION: IMPERIALISM 0x004a1f80
void TArmyMgr::FormStacks() {
  TArmyStack* stack = NULL;
  for (int tileIndex = 0; tileIndex < kProvinceCount; ++tileIndex) {
    TMilitaryUnit* unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain;
    short previousOrderTargetIndex = -1;
    short previousOwnerNationSlot = -1;
    for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
      short unitOrderTargetIndex = unit->orderTargetIndex;
      short unitOwnerNationSlot = unit->ownerNationSlot;
      if (unitOrderTargetIndex == -1) {
        if (unit->strength < 0x191) {
          unit->strength += 100;
        } else {
          unit->strength = 500;
        }
        if (unitOwnerNationSlot < 7 &&
            g_apNationStates[unitOwnerNationSlot]->diplomacyEligibility == 0) {
          unit->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        continue;
      }

      if (unitOrderTargetIndex != previousOrderTargetIndex ||
          unitOwnerNationSlot != previousOwnerNationSlot || stack == NULL) {
        bool foundExisting = false;
        int count = pendingUnitPool->GetCount();
        if (count != 0) {
          int index = 1;
          count = pendingUnitPool->GetCount();
          if (index <= count) {
            do {
              if (foundExisting) {
                break;
              }
              stack = static_cast<TArmyStack*>(pendingUnitPool->GetEntryByOrdinal(index));
              stack->AssertValid();
              if (stack->ownerNationCode == unitOrderTargetIndex &&
                  static_cast<short>(stack->categoryFlag) == unitOwnerNationSlot) {
                foundExisting = true;
              } else {
                ++index;
              }
              count = pendingUnitPool->GetCount();
            } while (index <= count);
          }
        }
        if (!foundExisting) {
          stack = new TArmyStack();
          stack->IArmyStack(static_cast<char>(unitOwnerNationSlot), unitOrderTargetIndex,
                            static_cast<short>(tileIndex));
          pendingUnitPool->listState.AddHead(stack);
        }
        previousOrderTargetIndex = unitOrderTargetIndex;
        previousOwnerNationSlot = unitOwnerNationSlot;
        if (stack == NULL) {
          FailNilPointerWithAssert(s_SourcePathUArmyMgr, 0x333);
        }
      }

      stack->AddUnit(unit);
    }
  }

  CIterator stackIter(pendingUnitPool);
  for (TArmyStack* item = static_cast<TArmyStack*>(stackIter.Reset()); stackIter.More();
       item = static_cast<TArmyStack*>(stackIter.Advance())) {
    item->ComputeStackCompositionClassCode();
  }

  pendingUnitPool->Sort();
  for (int i = 0; i < kProvinceCount; ++i) {
    perTileOwnerNationCodeCache[i] = g_pGlobalMapState->FindCountry(i);
  }
}

// FUNCTION: IMPERIALISM 0x004a2390
void TArmyMgr::ResolveNextMove() {
  bool battleViewCreated = false;
  if (ourStackBattle != NULL) {
    ourStackBattle->Free();
  }
  ourStackBattle = NULL;
  if (enemyStackBattle != NULL) {
    enemyStackBattle->Free();
  }
  enemyStackBattle = NULL;
  if (activeBattleView != NULL) {
    activeBattleView->Free();
  }
  activeBattleView = NULL;

  int stackCount = pendingUnitPool->GetCount();
  if (nextStackOrdinal <= stackCount) {
    while (!battleViewCreated) {
      int cursor = nextStackOrdinal;
      stackCount = pendingUnitPool->GetCount();
      if (stackCount < cursor) {
        break;
      }
      nextStackOrdinal = cursor + 1;
      TArmyStack* stack = static_cast<TArmyStack*>(pendingUnitPool->GetEntryByOrdinal(cursor));
      stack->AssertValid();
      if (perTileOwnerNationCodeCache[stack->ownerNationCode] ==
          static_cast<short>(stack->categoryFlag)) {
        stack->MoveAll();
      } else {
        battleViewCreated = ResolveConflict(stack, stack->ownerNationCode);
      }
    }
    stackCount = pendingUnitPool->GetCount();
    if (nextStackOrdinal <= stackCount) {
      return;
    }
    if (battleViewCreated) {
      return;
    }
  }
  EndBattlePhase();
}

// FUNCTION: IMPERIALISM 0x004a2500
void TArmyMgr::ClearPendingStacksAndFinalizeMilitaryUnits() {
  pendingUnitPool->FreePayloads();
  g_pGlobalMapState->DimmingOff();

  for (int i = 0; i < kTerrainTypeDescriptorTableCount; ++i) {
    TCountry* nation = g_apTerrainTypeDescriptorTable[i];
    if (nation == NULL) {
      continue;
    }
    TSortedList* unitList = nation->militaryUnitList;
    if (unitList == NULL) {
      FailNilPointerWithAssert(s_SourcePathUArmyMgr, 0x39b);
    }

    CIterator unitIter(unitList);
    for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
      if (unit->strength > 0 && unit->tileIndex != -1) {
        unit->ContinueOrders();
      } else {
        unit->Vaporize();
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
    CString separator(g_szListSeparator);
    AppendTextIntoFixedBuffer(destination->data, 0xff, static_cast<LPCSTR>(separator));
  }
  AppendTextIntoFixedBuffer(destination->data, 0xff, static_cast<LPCSTR>(formattedLabel));
}

// FUNCTION: IMPERIALISM 0x004a2900
static void BuildArmyContextActionRecordsAndDispatchLabel(TArmyStack* ourStack,
                                                          TArmyStack* enemyStack,
                                                          unsigned char sideWonFlag,
                                                          int ownerNationCodeInt, int unused) {

  MapContextActionRecord record;
  record.childCount[1] = 0;
  record.childCount[0] = 0;
  record.sideChildRecords[1] = 0;
  record.sideChildRecords[0] = 0;
  record.nationIds[1] = enemyStack->categoryFlag;
  record.nationIds[0] = ourStack->categoryFlag;
  record.location = reinterpret_cast<void*>(ownerNationCodeInt);
  record.reportKind = kMapContextReportLandBattle;
  record.displayedParticipantIndex = 0;

  if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(ourStack->categoryFlag,
                                                         enemyStack->categoryFlag)) {
    record.reportKind = kMapContextReportPreemptedLandBattle;
  } else if (enemyStack->ResetCursorAndGetHeadUnit() == 0) {
    record.reportKind = kMapContextReportUncontestedTakeover;
  }

  const int kUnitTypeSlotCount = 30;
  int ourCount[kUnitTypeSlotCount] = {0};
  int ourActiveCount[kUnitTypeSlotCount] = {0};
  int enemyCount[kUnitTypeSlotCount] = {0};
  int enemyActiveCount[kUnitTypeSlotCount] = {0};
  TMilitaryUnit* ourBestUnit = 0;
  for (TMilitaryUnit* unit = ourStack->ResetCursorAndGetHeadUnit(); unit != 0;
       unit = ourStack->AdvanceCursorAndGetUnit()) {
    ++record.childCount[0];
    ++ourCount[unit->orderType];
    if (unit->strength > 0) {
      ++ourActiveCount[unit->orderType];
    }
    if (unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1) &&
        (ourBestUnit == 0 ||
         unit->experiencePercent / 100 > ourBestUnit->experiencePercent / 100)) {
      ourBestUnit = unit;
    }
  }

  TMilitaryUnit* enemyBestUnit = 0;
  for (TMilitaryUnit* enemyUnit = enemyStack->ResetCursorAndGetHeadUnit(); enemyUnit != 0;
       enemyUnit = enemyStack->AdvanceCursorAndGetUnit()) {
    ++record.childCount[1];
    ++enemyCount[enemyUnit->orderType];
    if (enemyUnit->strength > 0) {
      ++enemyActiveCount[enemyUnit->orderType];
    }
    if (enemyUnit->orderType >= EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1) &&
        (enemyBestUnit == 0 ||
         enemyUnit->experiencePercent / 100 > enemyBestUnit->experiencePercent / 100)) {
      enemyBestUnit = enemyUnit;
    }
  }

  delete[] record.sideChildRecords[0];
  record.sideChildRecords[0] = new MapOrderBattleSideChildRecord[record.childCount[0]];
  delete[] record.sideChildRecords[1];
  record.sideChildRecords[1] = new MapOrderBattleSideChildRecord[record.childCount[1]];

  int childIndex = 0;
  for (TMilitaryUnit* ourRecordUnit = ourStack->ResetCursorAndGetHeadUnit(); ourRecordUnit != 0;
       ourRecordUnit = ourStack->AdvanceCursorAndGetUnit()) {
    MapOrderBattleSideChildRecord& child = record.sideChildRecords[0][childIndex];
    child.resourceType = ourRecordUnit->orderType;
    child.stockOrRequired = ourRecordUnit->strength;
    if (child.stockOrRequired == -86) {
      child.stockOrRequired = 0;
    }
    CString unitName;
    unitName = ourRecordUnit->name;
    CopyTextIntoFixedBuffer(child.nameBuffer, 0x20, static_cast<LPCSTR>(unitName));
    child.detailIdentity = kControlTagArmy;
    child.strengthBucket = static_cast<short>(ourRecordUnit->experiencePercent / 100);
    ++childIndex;
  }

  childIndex = 0;
  for (TMilitaryUnit* enemyRecordUnit = enemyStack->ResetCursorAndGetHeadUnit();
       enemyRecordUnit != 0; enemyRecordUnit = enemyStack->AdvanceCursorAndGetUnit()) {
    MapOrderBattleSideChildRecord& child = record.sideChildRecords[1][childIndex];
    child.resourceType = enemyRecordUnit->orderType;
    child.stockOrRequired = enemyRecordUnit->strength;
    if (child.stockOrRequired == -86) {
      child.stockOrRequired = 0;
    }
    CString unitName;
    unitName = enemyRecordUnit->name;
    CopyTextIntoFixedBuffer(child.nameBuffer, 0x20, static_cast<LPCSTR>(unitName));
    child.detailIdentity = kControlTagArmy;
    child.strengthBucket = static_cast<short>(enemyRecordUnit->experiencePercent / 100);
    ++childIndex;
  }

  CString formattedName;
  CString nationName;
  CString nameTemplate;
  g_pSimMgr->GetString(0x273d, 0x10, &nameTemplate);
  g_apTerrainTypeDescriptorTable[ourStack->categoryFlag]->FormatOverlayTerrainLabelText(
      &nationName);
  scanBracketExpressions(g_pSimMgr, &formattedName, static_cast<LPCSTR>(nameTemplate),
                         static_cast<LPCSTR>(nationName));
  CopyTextIntoFixedBuffer(record.nameBuffer[0].data, 0x20, static_cast<LPCSTR>(formattedName));

  g_pSimMgr->GetString(0x273d, 0x11, &nameTemplate);
  g_apTerrainTypeDescriptorTable[enemyStack->categoryFlag]->FormatOverlayTerrainLabelText(
      &nationName);
  scanBracketExpressions(g_pSimMgr, &formattedName, static_cast<LPCSTR>(nameTemplate),
                         static_cast<LPCSTR>(nationName));
  CopyTextIntoFixedBuffer(record.nameBuffer[1].data, 0x20, static_cast<LPCSTR>(formattedName));

  CopyTextIntoFixedBuffer(record.overlayLabel[1].data, 0xff, g_szEmptyString);
  CopyTextIntoFixedBuffer(record.overlayLabel[0].data, 0xff, record.overlayLabel[1].data);
  record.reportParticipantIndex = sideWonFlag == 0;

  for (int unitTypeIndex = 0; unitTypeIndex < kUnitTypeSlotCount; ++unitTypeIndex) {
    BuildArmyActionLabelFromLocalizationAndCounts(&record.overlayLabel[0], ourCount[unitTypeIndex],
                                                  ourActiveCount[unitTypeIndex], unitTypeIndex);
    BuildArmyActionLabelFromLocalizationAndCounts(&record.overlayLabel[1],
                                                  enemyCount[unitTypeIndex],
                                                  enemyActiveCount[unitTypeIndex], unitTypeIndex);
  }

  g_pMapContextActionManager->mapContextActionRecordList->AppendCopiedRecordToPtrList(&record);
  record.sideChildRecords[1] = 0;
  record.sideChildRecords[0] = 0;
  record.childCount[1] = 0;
  record.childCount[0] = 0;
  g_pMapContextActionManager->battlesToReport = true;
  if (g_bRandomMapDeveloperCheatFlag) {
    g_pMapContextActionManager->battlesToReport = true;
  }

  (void)ourBestUnit;
  (void)enemyBestUnit;
}

// FUNCTION: IMPERIALISM 0x004a3200
bool TArmyMgr::ResolveConflict(TArmyStack* stack, short ownerNationCode) {
  bool tacticalViewCreated = false;
  TMilitaryUnit* curUnit = stack->ResetCursorAndGetHeadUnit();

  TArmyStack* ourStack = new TArmyStack();
  ourStack->IArmyStack(static_cast<char>(curUnit->ownerNationSlot), ownerNationCode,
                       curUnit->tileIndex);

  while (curUnit != NULL) {
    if (curUnit->orderTargetIndex == ownerNationCode) {
      ourStack->AddUnit(curUnit);
    }
    curUnit = stack->AdvanceCursorAndGetUnit();
  }

  TArmyStack* enemyStack = NULL;
  if (ourStack->unitCount != 0) {
    int ownerNationCodeInt = ownerNationCode;
    short cachedOwnerAtTile = perTileOwnerNationCodeCache[ownerNationCodeInt];

    enemyStack = new TArmyStack();
    enemyStack->IArmyStack(static_cast<char>(cachedOwnerAtTile), ownerNationCode, ownerNationCode);

    TMilitaryUnit* enemyUnit = NULL;
    if (ownerNationCode >= 0 && ownerNationCode < kProvinceCount) {
      enemyUnit = g_pGlobalMapState->cityScoreTable[ownerNationCodeInt].stationedUnitChain;
    }
    for (; enemyUnit != NULL; enemyUnit = static_cast<TMilitaryUnit*>(enemyUnit->nextAtLocation)) {
      enemyStack->AddUnit(enemyUnit);
    }

    if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(ourStack->categoryFlag,
                                                           cachedOwnerAtTile)) {
      BuildArmyContextActionRecordsAndDispatchLabel(ourStack, enemyStack, 0, ownerNationCodeInt, 0);
      RetreatAttacker(ourStack);
    } else if (enemyStack->unitCount != 0) {
      tacticalViewCreated = true;
      CreateTacticalBattleViewAndInitializeBattleSetup(ourStack, enemyStack, ownerNationCodeInt);
    } else {
      BuildArmyContextActionRecordsAndDispatchLabel(ourStack, enemyStack, 1, ownerNationCodeInt, 0);
      ourStack->MoveAll();
      perTileOwnerNationCodeCache[ownerNationCodeInt] = ourStack->categoryFlag;
    }
  }

  if (!tacticalViewCreated) {
    if (ourStack != NULL) {
      ourStack->Free();
    }
    if (enemyStack != NULL) {
      enemyStack->Free();
    }
  }
  return tacticalViewCreated;
}

// FUNCTION: IMPERIALISM 0x004a35e0
void TArmyMgr::RetreatDefender(TArmyStack* stack, short tileIndex) {
  TMilitaryUnit* headUnit = stack->ResetCursorAndGetHeadUnit();
  short headUnitTag = headUnit->ownerNationSlot;

  const Province& record = g_pGlobalMapState->cityScoreTable[tileIndex];
  short candidateRegions[12];
  int candidateCount = 0;
  for (int i = 0; i < 24; ++i) {
    short regionId = record.adjacentRegionIds[i];
    if (regionId == -1) {
      break;
    }
    if (perTileOwnerNationCodeCache[regionId] == headUnitTag) {
      candidateRegions[candidateCount] = regionId;
      ++candidateCount;
    }
  }

  if (candidateCount == 0) {
    for (TMilitaryUnit* unit = stack->ResetCursorAndGetHeadUnit(); unit != 0;
         unit = stack->AdvanceCursorAndGetUnit()) {
      if (unit->strength != 0) {
        unit->Vaporize();
      }
    }
    return;
  }

  short chosenRegion = candidateRegions[rand() % candidateCount];
  for (TMilitaryUnit* unit = stack->ResetCursorAndGetHeadUnit(); unit != 0;
       unit = stack->AdvanceCursorAndGetUnit()) {
    if (g_awTacticalUnitCategoryCodeBySlot[unit->orderType] == 0) {
      unit->Vaporize();
    } else {
      unit->SetOrders(kUnitOrderRedeploy, chosenRegion);
    }
  }

  stack->MoveAll();
}

// FUNCTION: IMPERIALISM 0x004a37b0
void TArmyMgr::RetreatAttacker(TArmyStack* stack) {
  for (TMilitaryUnit* unit = stack->ResetCursorAndGetHeadUnit(); unit != 0;
       unit = stack->AdvanceCursorAndGetUnit()) {
    unit->SetOrders(kUnitOrderIdle, -1);
    if (unit->tileIndex != stack->tileIndex) {
      unit->MoveTo(stack->tileIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a3830
bool TArmyMgr::StrategicCombat(TArmyStack* stack1, TArmyStack* stack2) {
  TMilitaryUnit* unit = stack1->ResetCursorAndGetHeadUnit();
  while (unit != NULL) {
    stack1->fortLevelAttackerPenaltyCache = static_cast<unsigned char>(
        g_anFortLevelAttackerPenaltyPercentByLevel
            [g_pGlobalMapState->cityScoreTable[unit->tileIndex].fortLevel]);
    if (stack1->fortLevelAttackerPenaltyCache == 0) {
      break;
    }
    unit->strengthSnapshot = unit->strength;
    unit->SetOrClearBattleStateFlags(1, false);
    unit->SetOrClearBattleStateFlags(2, false);
    unit = stack1->AdvanceCursorAndGetUnit();
  }

  unit = stack2->ResetCursorAndGetHeadUnit();
  while (unit != NULL) {
    stack2->fortLevelAttackerPenaltyCache = static_cast<unsigned char>(
        g_anFortLevelAttackerPenaltyPercentByLevel
            [g_pGlobalMapState->cityScoreTable[unit->tileIndex].fortLevel]);
    if (stack2->fortLevelAttackerPenaltyCache == 0) {
      break;
    }
    unit->strengthSnapshot = unit->strength;
    bool blinkFlag = g_abUnitTypeBlinkEligibilityFlag[unit->orderType] != 0;
    unit->SetOrClearBattleStateFlags(1, blinkFlag);
    unit->SetOrClearBattleStateFlags(2, false);
    unit = stack2->AdvanceCursorAndGetUnit();
  }

  int counter = 0;
  while (true) {
    if (!stack1->UnitsFighting()) {
      break;
    }
    if (!stack2->UnitsFighting()) {
      break;
    }

    int sum1 = 0;
    int count1 = 0;
    int sum2 = 0;
    int count2 = 0;
    stack1->StrategicFirepower(&sum1, &count1, counter);
    stack2->StrategicFirepower(&sum2, &count2, counter);
    stack1->ApplyStrategicDamage(sum1, count1, counter);
    stack2->ApplyStrategicDamage(sum2, count2, counter);
    ++counter;
  }

  if (stack1->UnitsFighting()) {
    stack1->RaiseExperience(true);
    stack2->RaiseExperience(false);
    return true;
  }
  stack1->RaiseExperience(false);
  stack2->RaiseExperience(true);
  return false;
}

// FUNCTION: IMPERIALISM 0x004a3bc0
void TArmyMgr::DoOwnershipChanges() {
  for (int tileIndex = 0; tileIndex < kProvinceCount; ++tileIndex) {
    short cachedOwner = perTileOwnerNationCodeCache[tileIndex];
    signed char currentOwner = g_pGlobalMapState->cityScoreTable[tileIndex].ownerNationCode;
    if (currentOwner == -1 || cachedOwner == currentOwner) {
      continue;
    }
    if (g_apTerrainTypeDescriptorTable[currentOwner]->IsColonyOf(cachedOwner)) {
      continue;
    }

    bool proceed = true;
    if (cachedOwner < 7 && currentOwner > 6 &&
        g_apTerrainTypeDescriptorTable[currentOwner]->encodedNationSlot == -1) {
      bool eligible = g_pSimMgr->ReallyInTheGame(cachedOwner);
      bool blockedByPeerBand = g_apNationStates[cachedOwner] != NULL &&
                               g_apNationStates[cachedOwner]->encodedNationSlot > 99 &&
                               g_apNationStates[cachedOwner]->encodedNationSlot < 200;
      if (!eligible || blockedByPeerBand) {
        proceed = false;
      }
    }
    if (!proceed) {
      continue;
    }

    signed char primaryOwner = g_pGlobalMapState->cityScoreTable[tileIndex].ownerNationCode;
    signed char secondaryOwner = g_pGlobalMapState->cityScoreTable[tileIndex].formerOwnerNationCode;
    if (g_apTerrainTypeDescriptorTable[primaryOwner]->GetCapitolProvince() == tileIndex) {
      g_apTerrainTypeDescriptorTable[primaryOwner]->ChangeMaster(cachedOwner, 0);
    } else if (g_apTerrainTypeDescriptorTable[secondaryOwner] != NULL &&
               g_apTerrainTypeDescriptorTable[secondaryOwner]->GetCapitolProvince() == tileIndex) {
      g_apTerrainTypeDescriptorTable[secondaryOwner]->BecomeProtectorateOf(cachedOwner);
    }
    g_pGlobalMapState->ChangeProvinceOwner(static_cast<short>(tileIndex), cachedOwner);
    needsTerrainRefreshFlag = true;
  }
}

// FUNCTION: IMPERIALISM 0x004a3d90
void TArmyMgr::OrderArmies(int contextArg, short tileActionCode) {
  if (tileActionCode == 1 || tileActionCode == 4) {
    MoveArmies(contextArg);
  } else if (tileActionCode == 7) {
    DeploySelectedArmies(contextArg);
  }

  TMilitaryUnit* unit = NULL;
  if (pendingMapActionIndex >= 0 && pendingMapActionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex].stationedUnitChain;
  }
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 4) {
      unit->SetOrders(kUnitOrderIdle, -1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a3e50
bool TArmyMgr::MoveArmies(int contextArg) {
  TMilitaryUnit* unit = NULL;
  if (pendingMapActionIndex >= 0 && pendingMapActionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex].stationedUnitChain;
  }
  bool foundMovableUnit = false;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      unit->SetOrders(kUnitOrderRedeploy, contextArg);
      foundMovableUnit = true;
    }
  }
  if (foundMovableUnit) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aa7, 0, 1);
    g_pGlobalMapState->ActivateMarchingArrow(pendingMapActionIndex, contextArg, false);
  }
  return foundMovableUnit;
}

// FUNCTION: IMPERIALISM 0x004a3f30
bool TArmyMgr::DeploySelectedArmies(int contextArg) {
  TMilitaryUnit* unit = NULL;
  if (pendingMapActionIndex >= 0 && pendingMapActionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex].stationedUnitChain;
  }
  int totalCost = 0;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      totalCost += unit->GetArmsCarried();
    }
  }

  short nationSlot = g_pSimMgr->GetPlayerCountry();
  if (totalCost == 0) {
    return false;
  }

  TGreatPower* nation = g_apNationStates[nationSlot];
  if (totalCost <= nation->armyTransportRemaining) {
    MoveArmies(contextArg);
    nation->armyTransportRemaining -= totalCost;
    return true;
  }

  CString currentAmountString;
  currentAmountString.Format("%d", nation->armyTransportRemaining);
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
int TArmyMgr::GetSelectedForceSize() {
  TMilitaryUnit* unit = NULL;
  if (pendingMapActionIndex >= 0 && pendingMapActionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex].stationedUnitChain;
  }
  int totalCost = 0;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      totalCost += unit->GetArmsCarried();
    }
  }
  return totalCost;
}

// FUNCTION: IMPERIALISM 0x004a4260
void TArmyMgr::OrderSelectedArmies(int mode) {
  TMilitaryUnit* unit = NULL;
  if (pendingMapActionIndex >= 0 && pendingMapActionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex].stationedUnitChain;
  }
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0) {
      unit->SetOrders(static_cast<UnitOrder>(mode), -1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a42e0
void TArmyMgr::DoTacticalCombat(TArmyStack* ourStack, TArmyStack* enemyStack, int battleContext) {
  for (int unitType = 0; unitType < 30; ++unitType) {
    tacticalCombatUnitCountByType[1][unitType] = 0;
    tacticalCombatUnitCountByType[0][unitType] = 0;
  }

  tacticalCombatContext = static_cast<short>(battleContext);
  tacticalCombatNationCode[0] = ourStack->categoryFlag;
  tacticalCombatNationCode[1] = enemyStack->categoryFlag;

  for (TMilitaryUnit* unit = ourStack->ResetCursorAndGetHeadUnit(); unit != 0;
       unit = ourStack->AdvanceCursorAndGetUnit()) {
    ++tacticalCombatUnitCountByType[0][unit->orderType];
  }

  for (TMilitaryUnit* enemyUnit = enemyStack->ResetCursorAndGetHeadUnit(); enemyUnit != 0;
       enemyUnit = enemyStack->AdvanceCursorAndGetUnit()) {
    ++tacticalCombatUnitCountByType[1][enemyUnit->orderType];
  }
}

// FUNCTION: IMPERIALISM 0x004a43f0
short TArmyMgr::SelectUnitType(short categoryId, short tileIndex) {
  TMilitaryUnit* unit = NULL;
  if (tileIndex >= 0 && tileIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain;
  }

  bool activatedUnit = false;
  short remainingIdleCount = 0;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
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
short TArmyMgr::DeSelectUnitType(short categoryId, short tileIndex) {
  TMilitaryUnit* unit = NULL;
  if (tileIndex >= 0 && tileIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[tileIndex].stationedUnitChain;
  }

  bool deactivatedUnit = false;
  short idleCount = 0;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
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
bool TArmyMgr::AnySelectableUnits(short regionId) {
  if (regionId == -1) {
    return false;
  }
  TMilitaryUnit* unit = NULL;
  if (regionId >= 0 && regionId < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain;
  }
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004a45e0
void TArmyMgr::SetSelectedProvince(short cityRecordIndex) {
  pendingMapActionIndex = cityRecordIndex;
  if (cityRecordIndex != -1) {
    TMilitaryUnit* unit;
    if (cityRecordIndex >= 0 && cityRecordIndex < kProvinceCount) {
      unit = g_pGlobalMapState->cityScoreTable[cityRecordIndex].stationedUnitChain;
    } else {
      unit = NULL;
    }
    for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
      int orderState = unit->unitOrder;
      if ((static_cast<short>(orderState) == 4 || static_cast<short>(orderState) == 3) &&
          g_awTacticalUnitCategoryCodeBySlot[unit->orderType] != 0) {
        unit->SetOrders(kUnitOrderIdle, -1);
      }
    }
    TMapUberPicture* mapView = g_pViewMgr->mapUberPicture;
    static_cast<TArmyToolbar*>(mapView->categoryPages[mapView->activeUnitCategoryIndex])
        ->SetProvince(cityRecordIndex);
  }
  g_pViewMgr->mapUberPicture->InvalidateMap();
}

// FUNCTION: IMPERIALISM 0x004a46d0
void TArmyMgr::ResetCycle(short nationId) {
  TSortedList* unitList = g_apNationStates[nationId]->militaryUnitList;
  for (short ordinal = 1; ordinal <= unitList->GetCount(); ++ordinal) {
    TUnit* unit = static_cast<TUnit*>(unitList->GetEntryByOrdinal(ordinal));
    if (unit->unitOrder == 3) {
      unit->SetOrders(kUnitOrderIdle, -1);
    }
  }
  pendingMapActionIndex = -1;
}

// FUNCTION: IMPERIALISM 0x004a4760
short TArmyMgr::Cycle(short nationId) {
  short candidate = pendingMapActionIndex;
  if (candidate == -1) {
    candidate = 0;
  }

  while (candidate < kProvinceCount) {
    const Province& cityRecord = g_pGlobalMapState->cityScoreTable[candidate];
    short ownerNation = cityRecord.ownerNationCode;
    bool ownerPermitsSelection = false;
    if (ownerNation > -1) {
      ownerPermitsSelection = ownerNation == nationId ||
                              g_apTerrainTypeDescriptorTable[ownerNation]->IsColonyOf(nationId);
    }

    if (ownerPermitsSelection) {
      TMilitaryUnit* unit = cityRecord.stationedUnitChain;
      while (unit != NULL) {
        if (unit->unitOrder == 0 &&
            unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
          return candidate;
        }
        unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
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
    if (g_pViewMgr->mapUberPicture != NULL) {
      g_pViewMgr->mapUberPicture->SetMapInteractionMode(1);
      SetSelectedProvince(cityRecordIndex);
      handled = true;
    }
    break;
  case 6:
    MarchSelectedArmies(tileIndex);
    return true;
  case 8:
    ShowSpyReport(cityRecordIndex);
    return true;
  }
  return handled;
}

// FUNCTION: IMPERIALISM 0x004a4930
unsigned short TArmyMgr::LookupMapCursorTokenByStateIndex(short tileIndex, short mode) {
  return g_mapCursorTokenByStateIndex[ComputeMapCursorStateIndex(tileIndex, mode)];
}

// FUNCTION: IMPERIALISM 0x004a4960
static int __stdcall ComputeMapCursorStateIndex(short tileIndex, short mode) {
  TTerrainStateRecord* rec = &g_pGlobalMapState->terrainStateTable[tileIndex];
  if (rec->perTileVisitedFlag > 0) {
    return 6;
  }
  if (mode != 2) {
    if (g_pViewMgr->mapUberPicture->IsAUnitSelected()) {
      return 0;
    }
    if (mode != 2 && rec->firstCivilianOrder != NULL) {
      return 0;
    }
  }
  if (((rec->activeFlags >> 5) & 1) == 0) {
    return 0;
  }
  short ownerTag = rec->ownerNationTag;
  short activeNationId = g_pSimMgr->GetPlayerCountry();
  if (!g_pSimMgr->ReallyInTheGame(activeNationId)) {
    return 8;
  }
  activeNationId = g_pSimMgr->GetPlayerCountry();
  if (ownerTag != activeNationId) {
    TCountry* owner = g_apTerrainTypeDescriptorTable[ownerTag];
    activeNationId = g_pSimMgr->GetPlayerCountry();
    if (!owner->IsColonyOf(activeNationId)) {
      return 8;
    }
  }
  return 2;
}

// FUNCTION: IMPERIALISM 0x004a4aa0
unsigned short TArmyMgr::LookupCivilianMapCursorTokenByStateIndex(short tileIndex, short mode) {
  return g_civilianMapCursorTokenByStateIndex[GetTileSelection(tileIndex, mode)];
}

// FUNCTION: IMPERIALISM 0x004a4ad0
bool TArmyMgr::HandleMapClickByCivilianCursorState(short tileIndex, short mode) {
  int cursorState = GetTileSelection(tileIndex, mode);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  switch (cursorState) {
  case 2:
    SetSelectedProvince(cityRecordIndex);
    return false;
  case 3:
  case 4:
    break;
  case 5:
    return ValidateOrderPlacementPrerequisitesForSelectedTile(cityRecordIndex);
  case 6:
    MarchSelectedArmies(tileIndex);
    return false;
  case 7:
    g_pViewMgr->MakeGarrisonWindow(pendingMapActionIndex);
    return false;
  case 8:
    ShowSpyReport(cityRecordIndex);
    // fall through
  default:
    return false;
  }

  const Province& selectedTile = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex];
  bool cityIsAdjacent = false;
  for (short i = 0; i < selectedTile.adjacentRegionCount; ++i) {
    if (selectedTile.adjacentRegionIds[i] == cityRecordIndex) {
      cityIsAdjacent = true;
      break;
    }
  }
  if (cityIsAdjacent) {
    return MoveArmies(cityRecordIndex);
  }
  return DeploySelectedArmies(cityRecordIndex);
}

// FUNCTION: IMPERIALISM 0x004a4c80
int TArmyMgr::GetTileSelection(short tileIndex, short mode) {
  if (pendingMapActionIndex == -1) {
    return ComputeMapCursorStateIndex(tileIndex, mode);
  }

  TTerrainStateRecord* rec = &g_pGlobalMapState->terrainStateTable[tileIndex];
  if (rec->perTileVisitedFlag > 0) {
    return 6;
  }
  short cityRecordIndex = rec->cityRecordIndex;
  if (cityRecordIndex == -1) {
    return 1;
  }

  short pendingSlot = g_pGlobalMapState->FindCountry(pendingMapActionIndex);
  short citySlot = g_pGlobalMapState->FindCountry(cityRecordIndex);

  TMilitaryUnit* unit = NULL;
  if (pendingMapActionIndex >= 0 && pendingMapActionIndex < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[pendingMapActionIndex].stationedUnitChain;
  }
  bool hasMovableUnit = false;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      hasMovableUnit = true;
      break;
    }
  }

  if (cityRecordIndex == pendingMapActionIndex) {
    return ((rec->activeFlags >> 5) & 1) != 0 ? 7 : 0;
  }

  bool sameOwner = pendingSlot == citySlot;
  if (!sameOwner) {
    TCountry* cityOwnerCountry = g_apTerrainTypeDescriptorTable[citySlot];
    sameOwner = cityOwnerCountry->IsColonyOf(pendingSlot);
  }

  if (sameOwner) {
    if (((rec->activeFlags >> 5) & 1) != 0) {
      return 2;
    }
    if (!hasMovableUnit) {
      return 1;
    }
    return g_pGlobalMapState->IsProvinceAdjacentTo(pendingMapActionIndex, cityRecordIndex) ? 3 : 4;
  }

  if (((rec->activeFlags >> 5) & 1) != 0) {
    return 8;
  }
  if (!hasMovableUnit) {
    return 1;
  }
  if (!g_pDiplomacyTurnStateManager->AreAtWar(pendingSlot, citySlot)) {
    return 1;
  }
  if (g_pGlobalMapState->IsProvinceAdjacentTo(pendingMapActionIndex, cityRecordIndex)) {
    return 5;
  }
  if ((g_pGlobalMapState->cityScoreTable[cityRecordIndex].exploredByNationMask >> pendingSlot) &
      1) {
    return 5;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004a4fc0
void TArmyMgr::DispatchMapActionForRegionByAdjacency(int contextArg) {
  bool isAdjacent = false;
  short index = 0;
  Province* province = &g_pGlobalMapState->cityScoreTable[pendingMapActionIndex];
  short adjacentCount = province->adjacentRegionCount;
  if (adjacentCount > 0) {
    do {
      if (isAdjacent) {
        break;
      }
      if (province->adjacentRegionIds[index] == static_cast<short>(contextArg)) {
        isAdjacent = true;
      }
      ++index;
    } while (index < adjacentCount);
  }
  if (!isAdjacent) {
    DeploySelectedArmies(contextArg);
    return;
  }
  MoveArmies(contextArg);
}

// FUNCTION: IMPERIALISM 0x004a5080
bool TArmyMgr::ValidateOrderPlacementPrerequisitesForSelectedTile(short cityRecordIndex) {
  TMilitaryUnit* unit = g_pGlobalMapState->GetMilitaryMaster(pendingMapActionIndex);
  int totalCost = 0;
  for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      totalCost += unit->GetArmsCarried();
    }
  }
  if (totalCost == 0) {
    return false;
  }

  if (!g_pGlobalMapState->IsProvinceAdjacentTo(pendingMapActionIndex, cityRecordIndex)) {
    CString validationBody;
    CString validationTitle;
    if (!g_pGlobalMapState->HasPortInProvince(pendingMapActionIndex)) {
      g_pSimMgr->GetString(0x2745, 4, &validationBody);
      g_pSimMgr->GetString(0x2745, 5, &validationTitle);
      g_pViewMgr->ModalMessage(5, validationTitle, validationBody, g_ptArmyValidationModalMessage,
                               1, 0);
      return false;
    }

    if (!g_pGlobalMapState->HasActiveLinkedTileWithReachableSea(pendingMapActionIndex)) {
      g_pSimMgr->GetString(0x2745, 6, &validationBody);
      g_pSimMgr->GetString(0x2745, 7, &validationTitle);
      g_pViewMgr->ModalMessage(5, validationTitle, validationBody, g_ptArmyValidationModalMessage,
                               1, 0);
      return false;
    }

    short activeNationId = g_pSimMgr->GetPlayerCountry();
    TCountry* activeCountry = g_apTerrainTypeDescriptorTable[activeNationId];
    int reinforcementCost = 0;
    CIterator orderIter(activeCountry->militaryUnitList);
    for (TUnit* order = static_cast<TUnit*>(orderIter.Reset()); orderIter.More();
         order = static_cast<TUnit*>(orderIter.Advance())) {
      if (order->unitOrder == 1 && order->orderTargetIndex == cityRecordIndex &&
          !g_pGlobalMapState->IsProvinceAdjacentTo(order->tileIndex, cityRecordIndex)) {
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
                               static_cast<LPCSTR>(seaValueText),
                               static_cast<LPCSTR>(totalCostText));
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
  }

  for (unit = g_pGlobalMapState->GetMilitaryMaster(pendingMapActionIndex); unit != NULL;
       unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      unit->SetOrders(kUnitOrderRedeploy, cityRecordIndex);
    }
  }
  g_pGlobalMapState->ActivateMarchingArrow(pendingMapActionIndex, cityRecordIndex, true);

  if (g_pViewMgr->mapUberPicture != NULL) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x3aa7, 0, 1);
    g_pViewMgr->mapUberPicture->NoticeTile(
        g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex);
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x004a5760
void TArmyMgr::MarchSelectedArmies(short tileIndex) {
  short direction = (g_pGlobalMapState->terrainStateTable[tileIndex].perTileVisitedFlag - 1) % 6;
  short neighborTile = TMapMgr::GetNeighborTileID(tileIndex, direction);
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[neighborTile].cityRecordIndex;

  short activeNationId = g_pSimMgr->GetPlayerCountry();
  TGreatPower* nationState = g_apNationStates[activeNationId];
  int categoryCounts[10] = {0};

  unsigned char* unitOnTileFlags = new unsigned char[nationState->militaryUnitList->GetCount()];
  memset(unitOnTileFlags, 0, nationState->militaryUnitList->GetCount());

  CIterator unitIter(nationState->militaryUnitList);
  unsigned char* flagCursor = unitOnTileFlags;
  for (TUnit* unit = static_cast<TUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TUnit*>(unitIter.Advance())) {
    if (unit->orderTargetIndex == cityRecordIndex) {
      categoryCounts[g_awTacticalUnitCategoryCodeBySlot[unit->orderType]]++;
      *flagCursor = 1;
    }
    ++flagCursor;
  }

  if (!g_pViewMgr->MakeArmyInfoWindow(cityRecordIndex, categoryCounts)) {
    short activeNationId2 = g_pSimMgr->GetPlayerCountry();
    bool sameOwner =
        g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode == activeNationId2;

    flagCursor = unitOnTileFlags;
    for (TUnit* unit = static_cast<TUnit*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TUnit*>(unitIter.Advance())) {
      if (*flagCursor != 0) {
        if (sameOwner &&
            !g_pGlobalMapState->IsProvinceAdjacentTo(unit->tileIndex, cityRecordIndex)) {
          short cost = static_cast<TMilitaryUnit*>(unit)->GetArmsCarried();
          short activeNationId3 = g_pSimMgr->GetPlayerCountry();
          g_apNationStates[activeNationId3]->armyTransportRemaining += cost;
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
      unsigned char flag = g_pGlobalMapState->terrainStateTable[nt].perTileVisitedFlag;
      if (flag == 0) {
        continue;
      }
      if ((flag - 1) % 6 != (i + 3) % 6) {
        continue;
      }
      g_pGlobalMapState->terrainStateTable[nt].perTileVisitedFlag = 0;
      if (g_pViewMgr->mapUberPicture != NULL) {
        g_pViewMgr->mapUberPicture->InvalidateTile(nt);
      }
    }

    g_pGlobalMapState->ConfirmArrows();
    if (pendingMapActionIndex != -1) {
      SetSelectedProvince(pendingMapActionIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a5aa0
int TArmyMgr::GetLandForceIn(int nodeIndexArg) {
  short nodeIndex = nodeIndexArg;
  TMilitaryUnit* chain;
  if (nodeIndex < 0 || nodeIndex >= kProvinceCount) {
    chain = 0;
  } else {
    chain = g_pGlobalMapState->cityScoreTable[nodeIndex].stationedUnitChain;
  }
  int sum = 0;
  for (; chain != 0; chain = static_cast<TMilitaryUnit*>(chain->nextAtLocation)) {
    sum += g_anWeightedNeighborUnitScoreByType[chain->orderType];
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004a5b10
void TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup(TArmyStack* ourStack,
                                                                TArmyStack* enemyStack,
                                                                int ownerNationCodeInt) {
  int compositionClass = g_pGlobalMapState->ClassifyCityGateTerrainComposition(ownerNationCodeInt);
  short provinceIndex = ownerNationCodeInt;
  int fortLevel = g_pGlobalMapState->cityScoreTable[provinceIndex].fortLevel;
  if (fortLevel > 0) {
    fortLevel++;
  }

  TArmyBattle* newBattle = new TArmyBattle();
  newBattle->AllocateRecordList();
  newBattle->InitializeBattleSetupAndMaybeShowTacticalView(ourStack, enemyStack, compositionClass,
                                                           fortLevel, ownerNationCodeInt);

  ourStackBattle = ourStack;
  enemyStackBattle = enemyStack;
  activeBattleView = newBattle;

  bool isMultiplayerHost =
      static_cast<unsigned char>(g_pSimMgr->multiplayerSessionRole == kSessionRoleHost);
  if (isMultiplayerHost) {
    g_pGameFlowState->NoOpCallbackRet4(newBattle);
  }
  newBattle->StartBattle();
}

// FUNCTION: IMPERIALISM 0x004a5ca0
void TArmyMgr::EndTacticalBattle(TArmyStack* ourStack, TArmyStack* enemyStack,
                                 unsigned char sideWonFlag, int battleSiteIndex) {
  BuildArmyContextActionRecordsAndDispatchLabel(ourStack, enemyStack, sideWonFlag, battleSiteIndex,
                                                1);

  if (sideWonFlag != 0) {
    RetreatDefender(enemyStack, static_cast<short>(battleSiteIndex));
    ourStack->MoveAll();
    perTileOwnerNationCodeCache[battleSiteIndex] = ourStack->categoryFlag;
    ourStack->RaiseExperience(true);
    enemyStack->RaiseExperience(false);
  } else {
    RetreatAttacker(ourStack);
    ourStack->RaiseExperience(false);
    enemyStack->RaiseExperience(true);
  }
  ResolveNextMove();
}

// FUNCTION: IMPERIALISM 0x004a5ec0
bool TArmyMgr::GenerateSpyReport(int cityRecordIndex, CString& outDefenderSummary,
                                 CString& outGarrisonSummary) {
  int bestScore = -1;
  CString candidateName;

  int adjacentRegionCount = g_pGlobalMapState->cityScoreTable[cityRecordIndex].adjacentRegionCount;
  if (adjacentRegionCount > 0) {
    int i = 0;
    do {
      short regionId = g_pGlobalMapState->cityScoreTable[cityRecordIndex].adjacentRegionIds[i];
      if (g_pGlobalMapState->FindCountry(regionId) == g_pSimMgr->GetPlayerCountry()) {
        TMilitaryUnit* unit = NULL;
        if (regionId >= 0 && regionId < kProvinceCount) {
          unit = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain;
        }
        for (; unit != NULL; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation)) {
          if (unit->orderType >= EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1)) {
            int score = static_cast<short>(unit->experiencePercent / 100) + 1;
            if (bestScore < score) {
              candidateName = unit->name;
              outDefenderSummary = candidateName;
              bestScore = score;
            }
          }
        }
        if (bestScore < 0) {
          bestScore = 0;
          g_pGlobalMapState->AssignCityRecordDisplayName(regionId, &candidateName);
          g_pSimMgr->GetString(0x2744, 1, &outDefenderSummary);
          outDefenderSummary = CString(outDefenderSummary + s_szSpaceSeparator + candidateName);
        }
      }
      ++i;
    } while (i < adjacentRegionCount);
  }

  TShip* bestShip = NULL;
  for (TShip* ship = TShip::GetFirst(); ship != NULL; ship = ship->next) {
    if (ship->nation == g_pSimMgr->GetPlayerCountry() &&
        ship->location->ContainsCityStatePointerInZoneArrayByCityIndex(cityRecordIndex)) {
      bestShip = ship->Finest(bestShip, false);
    }
  }
  if (bestShip != NULL) {
    CString selectedName;
    TAdmiral* admiral = bestShip->admiral;
    if (admiral == NULL) {
      if (bestScore == -1) {
        selectedName = bestShip->name;
        g_pSimMgr->GetString(0x2744, 3, &outDefenderSummary);
        outDefenderSummary += s_szSpaceSeparator + selectedName;
        bestScore = 0;
      }
    } else {
      int admiralScore = static_cast<short>(admiral->experiencePoints / 100) + 1;
      if (bestScore < admiralScore) {
        selectedName = CString(s_szAdmiralPrefix + admiral->displayName);
        g_pSimMgr->GetString(0x2744, 2, &outDefenderSummary);
        outDefenderSummary += s_szSpaceSeparator + selectedName;
        bestScore = admiralScore;
      }
    }
  }

  if (bestScore == -1) {
    return false;
  }

  short activeNationId = g_pSimMgr->GetPlayerCountry();
  short turnTick = g_pSimMgr->GetEconomicTurn();
  int seed = cityRecordIndex + turnTick + activeNationId;
  if (seed == 0) {
    seed = cityRecordIndex;
  }

  int resourceBuckets[11];
  memset(resourceBuckets, 0, sizeof(resourceBuckets));
  short citySlot = cityRecordIndex;
  TMilitaryUnit* unit = NULL;
  if (citySlot >= 0 && citySlot < kProvinceCount) {
    unit = g_pGlobalMapState->cityScoreTable[citySlot].stationedUnitChain;
  }
  if (unit != NULL) {
    const short* pointCostWeights = g_MapOrderResourceRollWeightTable[bestScore];
    const short* categoryWeights = g_MapOrderResourceRollWeightTable[bestScore] + 3;
    do {
      seed = seed * 0x15a4e35 + 1;
      short pointCost = static_cast<short>(FindCumulativeWeightBucketIndex(
          const_cast<short*>(pointCostWeights),
          static_cast<int>(static_cast<unsigned int>(seed) >> 0xc & 0x7fff) % 100));
      seed = seed * 0x15a4e35 + 1;
      short category = static_cast<short>(
          FindCumulativeWeightBucketIndex(
              const_cast<short*>(categoryWeights),
              static_cast<int>(static_cast<unsigned int>(seed) >> 0xc & 0x7fff) % 100) +
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
      unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
      resourceBuckets[category] += pointCost;
    } while (unit != NULL);
  }

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
        outGarrisonSummary += g_szListSeparator;
      }
      g_pSimMgr->GetString(0x2726, static_cast<short>(count == 1 ? bucket : bucket + 0xb),
                           &resourceTypeName);
      countText.Format(g_szDecimalFormat, count);
      outGarrisonSummary += countText + s_szSpaceSeparator + resourceTypeName;
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
  if (!GenerateSpyReport(cityRecordIndex, defenderSummary, garrisonSummary)) {
    CString noSummaryMessage;
    g_pSimMgr->GetString(0x2744, 8, &noSummaryMessage);
    g_pViewMgr->ModalMessage(noSummaryMessage, g_ptArmyValidationModalMessage, 1, 0);
    return;
  }

  TWindow* node =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventEnemyFleetReport);
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUArmyMgr, 0xa4d);
  }
  node->SetModality(true);

  // MapView.rsrc view 9475's children, in the order the original fills them.
  CString scratchText;
  TStaticText* ownerLabel = static_cast<TStaticText*>(node->FindSubView(kControlTagGpee)); // 'gpee'
  ownerLabel->AssertValid();
  g_apTerrainTypeDescriptorTable[g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode]
      ->FormatOverlayTerrainLabelText(&scratchText);
  ownerLabel->SetTextAndMaybeRefresh(&scratchText, false);
  ownerLabel->InstallTextStyle(styleB, 0);

  TStaticText* zoneLabel = static_cast<TStaticText*>(node->FindSubView(kControlTagZone)); // 'zone'
  zoneLabel->AssertValid();
  CString cityDisplayName;
  g_pGlobalMapState->AssignCityRecordDisplayName(static_cast<ProvinceIndex>(cityRecordIndex),
                                                 &cityDisplayName);
  scratchText = cityDisplayName;
  zoneLabel->SetTextAndMaybeRefresh(&scratchText, false);
  zoneLabel->InstallTextStyle(styleB, 0);

  TStaticText* defenderLabel =
      static_cast<TStaticText*>(node->FindSubView(kControlTagAdam)); // 'adam'
  defenderLabel->AssertValid();
  defenderLabel->SetTextAndMaybeRefresh(&defenderSummary, false);
  defenderLabel->InstallTextStyle(styleC, 0);

  TStaticText* garrisonLabel =
      static_cast<TStaticText*>(node->FindSubView(kControlTagShip)); // 'ship'
  garrisonLabel->AssertValid();
  CString quotedGarrison = CString(g_szDoubleQuote) + garrisonSummary + g_szDoubleQuote;
  garrisonLabel->SetTextAndMaybeRefresh(&quotedGarrison, false);
  garrisonLabel->InstallTextStyle(styleC, 0);

  TStaticText* titleLabel = static_cast<TStaticText*>(node->FindSubView(kControlTagTitl)); // 'titl'
  titleLabel->AssertValid();
  titleLabel->SetTextWithStrListID(0x2744, 5, false);
  titleLabel->InstallTextStyle(styleA, 0);

  TStaticText* label1 = static_cast<TStaticText*>(node->FindSubView(kControlTagLab1));
  label1->AssertValid();
  label1->SetTextWithStrListID(0x2744, 6, false);
  label1->InstallTextStyle(styleC, 0);

  TStaticText* label2 = static_cast<TStaticText*>(node->FindSubView(kControlTagLab2));
  label2->AssertValid();
  label2->SetTextWithStrListID(0x2744, 7, false);
  label2->InstallTextStyle(styleC, 0);

  TStaticText* label3 = static_cast<TStaticText*>(node->FindSubView(kControlTagLab3));
  label3->AssertValid();
  label3->Show(0, 0);
  label3->InstallTextStyle(styleB, 0);

  TStaticText* label4 = static_cast<TStaticText*>(node->FindSubView(kControlTagLab4));
  label4->AssertValid();
  label4->SetTextWithStrListID(0x2744, 8, false);
  label4->InstallTextStyle(styleD, 0);

  TDialogBehavior* behavior = node->GetDialogBehavior();
  if (behavior != NULL) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x004a6d40
bool TArmyMgr::HasBattlesInvolvingGP(short activeNationId) const {
  int remaining = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
  if (remaining <= 0) {
    return false;
  }
  while (remaining > 0) {
    MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
        g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
            remaining));
    if (activeNationId == static_cast<signed char>(record->nationIds[0]) ||
        activeNationId == static_cast<signed char>(record->nationIds[1])) {
      return true;
    }
    if (g_bRandomMapDeveloperCheatFlag) {
      return true;
    }
    --remaining;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004a6dd0
bool TArmyMgr::HasBattlesToReport() const {
  return battlesToReport;
}

// FUNCTION: IMPERIALISM 0x004a6df0
void TArmyMgr::CleanUpStacks() {
  if (mapContextActionRecordList != 0) {
    int ordinal = g_pMapContextActionManager->mapContextActionRecordList->GetSize();
    while (ordinal > 0) {
      MapContextActionRecord* record = static_cast<MapContextActionRecord*>(
          g_pMapContextActionManager->mapContextActionRecordList->GetPtrListEntryByOneBasedIndex(
              ordinal));
      delete[] record->sideChildRecords[0];
      delete[] record->sideChildRecords[1];
      record->sideChildRecords[1] = 0;
      record->sideChildRecords[0] = 0;
      --ordinal;
    }
    mapContextActionRecordList->DeleteAll();
  }
  battlesToReport = false;
}

// FUNCTION: IMPERIALISM 0x004a6e80
void TArmyMgr::AddBattleRecord(MapOrderBattleSnapshot* record, int unusedArg2) {
  mapContextActionRecordList->AppendCopiedRecordToPtrList(record);
  record->childRecords[1] = NULL;
  record->childRecords[0] = NULL;
  record->childCount[1] = 0;
  record->childCount[0] = 0;
  battlesToReport = true;
}

// FUNCTION: IMPERIALISM 0x004a6ef0
void TArmyMgr::CheckForDrownedUnits(char nationId, int cityIndex,
                                    MapOrderBattleSnapshot* snapshot) {
  int side = (nationId != snapshot->nationIds[0]) ? 1 : 0;

  TList* scratchList = new TList();

  int budget = 0;
  TCountry* nation = g_apNationStates[static_cast<int>(nationId)];
  CIterator unitIter(nation->militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    if (unit->orderTargetIndex == cityIndex &&
        !g_pGlobalMapState->IsProvinceAdjacentTo(unit->tileIndex, cityIndex)) {
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
      if (pos != NULL) {
        scratchList->listState.RemoveAt(pos);
      }
      budget -= evicted->GetArmsCarried();
      ++evictedCount;
      evicted->strength = -86;
    } while (budget > 0);

    int oldCount = snapshot->childCount[side];
    MapOrderBattleSideChildRecord* oldRecords = snapshot->childRecords[side];
    int newCount = oldCount + evictedCount;
    snapshot->childCount[side] = static_cast<short>(newCount);

    MapOrderBattleSideChildRecord* newRecords = NULL;
    if (newCount > 0) {
      newRecords = new MapOrderBattleSideChildRecord[newCount];
    }
    snapshot->childRecords[side] = newRecords;
    memcpy(newRecords, oldRecords, oldCount * sizeof(MapOrderBattleSideChildRecord));

    if (evictedCount != 0) {
      int recordIndex = oldCount;
      for (int pass = 0; pass < evictedCount; ++pass) {
        CIterator evictedIter(nation->militaryUnitList);
        for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(evictedIter.Reset());
             evictedIter.More(); unit = static_cast<TMilitaryUnit*>(evictedIter.Advance())) {
          if (unit->strength == static_cast<short>(-86)) {
            unit->strength = 0;
            MapOrderBattleSideChildRecord& rec = newRecords[recordIndex];
            ++recordIndex;
            rec.resourceType = unit->orderType;
            rec.stockOrRequired = -86;
            rec.nameBuffer[0] = 0;
            CString unitName = unit->name;
            LPCSTR unitNameChars = static_cast<LPCSTR>(unitName);
            for (int c = 0; c < 32; ++c) {
              char ch = unitNameChars[c];
              rec.nameBuffer[c] = ch;
              if (ch == '\0') {
                break;
              }
            }
            rec.detailIdentity = kControlTagArmy; // 'army'
            rec.strengthBucket = static_cast<short>(unit->experiencePercent / 100);
            unit->Vaporize();
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
void TArmyMgr::ReassessLanding(int nationSlot, int zone) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  int totalArms = 0;
  CIterator cursor(nation->militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset()); cursor.More();
       unit = static_cast<TMilitaryUnit*>(cursor.Advance())) {
    if (unit->orderTargetIndex == zone) {
      if (!g_pGlobalMapState->IsProvinceAdjacentTo(unit->tileIndex, zone)) {
        totalArms += unit->GetArmsCarried();
      }
    }
  }
  short capacity = g_pNavyOrderManager->GetInvasionCapacity(
      static_cast<short>(nationSlot), &g_pGlobalMapState->cityScoreTable[zone], 0);
  if (totalArms - capacity > 0) {
    CString message;
    g_pSimMgr->GetString(0x2745, 10, &message);
    g_pViewMgr->ModalMessage(message, g_ptArmyValidationModalMessage);

    CIterator reassessCursor(nation->militaryUnitList);
    for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(reassessCursor.Reset());
         reassessCursor.More(); unit = static_cast<TMilitaryUnit*>(reassessCursor.Advance())) {
      if (unit->orderTargetIndex == zone &&
          !g_pGlobalMapState->IsProvinceAdjacentTo(unit->tileIndex, zone)) {
        unit->SetOrders(kUnitOrderIdle, -1);
      }
    }
    g_pGlobalMapState->ConfirmArrows();
  }
}

// FUNCTION: IMPERIALISM 0x004a7590
void TArmyMgr::WakeAll(int nationId) {
  TLongintList* regionList = g_apNationStates[nationId]->ownedRegionList;
  CLongintIterator regionIterator(regionList);
  short cityIndex = static_cast<short>(regionIterator.FirstLong());
  while (regionIterator.More()) {
    TMilitaryUnit* unit = g_pGlobalMapState->GetMilitaryMaster(cityIndex);
    while (unit != 0) {
      if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia) &&
          unit->unitOrder != 1) {
        unit->SetOrders(kUnitOrderIdle, -1);
      }
      unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
    }
    cityIndex = static_cast<short>(regionIterator.NextLong());
  }

  TMapUberPicture* mapView = g_pViewMgr->mapUberPicture;
  if (mapView != 0 && !mapView->IsAUnitSelected()) {
    mapView->CycleMapInteractionSelectionAfterHandledClick();
  }
}
