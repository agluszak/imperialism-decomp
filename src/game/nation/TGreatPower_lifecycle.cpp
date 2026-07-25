// TGreatPower lifecycle, stream serialization, and pending-action dispatch
// (ctor, Free, ReadFrom/WriteTo, status prompts, pending-action state
// machine). Split from TGreatPower.cpp along the address-contiguous
// 0x4d84b0-0x4db6xx region preceding the UCountry module sample
// (bd imperialism-decomp-8mo.15); the remaining TGreatPower.cpp holds the
// diplomacy/order/advisory bodies of the original Cross/UCountry.cpp.
// TGreatPower — nation-state object for the seven playable great powers
// (Mac source: UCountry.cpp / UCountryAuto.cpp). Manual decompilation file;
// reccmp pairs bodies by the FUNCTION address markers.

#include <math.h>
#include <stddef.h>
#include <string.h>

#include "decomp_types.h"
#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/ui_screens/CString.h"
#include "game/GameAssert.h"
#include "game/globals/prelude.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/nation_stream_serialization.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/navy/TAdmiral.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/military/TCivUnit.h"
#include "game/city_ui/TCountry.h"
#include "game/military/TDefendProvinceMission.h"
#include "game/military_ui/TDefenseMinister.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/map/TForeignMinister.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/map/TMinister.h"
#include "game/military/TMilitaryUnit.h"
#include "game/city_ui/TProvinceDesirabilityList.h"
#include "game/nation/TMinor.h"
#include "game/map/TMission.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/map/TNavyMission.h"
#include "game/app/TObject.h"
#include "game/navy/TOcean.h"
#include "game/city/TProductionOrder.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/ui_widgets/TTown.h"
#include "game/military/TUnit.h"
#include "game/ui_screens/turn_flow_cooldown.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TZone.h"
#include "game/gfx/ui_invalidation_guard.h"

static const int kDiplomacyTrackedSlotCount = 0x11;

// FUNCTION: IMPERIALISM 0x004d84b0
int TGreatPower::ClassifyNationMilitaryPowerBandAgainstGlobalMean() {
  float count = 0.0f;
  float sumPower = 0.0f;
  float sumPowerSq = 0.0f;

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (!g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot))) {
      continue;
    }

    TGreatPower* nation = g_apNationStates[nationSlot];
    int weightSum = 0;
    CIterator unitIter(nation->militaryUnitList44);
    for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
      weightSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
    }

    int power = weightSum + nation->SumNavyOrderPriorityForNationSlot86() + 4;
    sumPower += static_cast<float>(power);
    sumPowerSq += static_cast<float>(power * power);
    count += 1.0f;
  }

  if (count < 2.0f) {
    return 2;
  }

  float mean = sumPower / count;
  float stddev =
      sqrtf((sumPowerSq - 2.0f * mean * sumPower + mean * mean * count) / (count - 1.0f));

  int myWeightSum = 0;
  CIterator myUnitIter(this->militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(myUnitIter.Reset()); myUnitIter.More();
       unit = static_cast<TMilitaryUnit*>(myUnitIter.Advance())) {
    myWeightSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  float myPower = static_cast<float>(myWeightSum + this->SumNavyOrderPriorityForNationSlot86() + 4);

  if (myPower > mean + 2.0f * stddev) {
    return 4;
  }
  if (myPower > mean + stddev) {
    return 3;
  }
  if (myPower <= mean - stddev) {
    return 2;
  }
  if (myPower >= mean - 2.0f * stddev) {
    return 1;
  }
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004d8950
// TGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d89d0
// TGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGreatPower, TCountry)

// FUNCTION: IMPERIALISM 0x004d89f0
TGreatPower::TGreatPower()
    : foreignMinister(0), interiorMinister(0), defenseMinister(0), diplomacyEligibilityA0(0),
      diplomacyCounterA2(0), tradeCapacity(0), needCapA6(0), needsOverCapFlag(0), grantTotalCost(0),
      diplomacyCounterB0(0), budgetPoolBase(0), budgetPoolDelta(0), turnEventQueue(0),
      proposalQueue(0), city(0), townMarkerList(0), trackedObjectList(0), scenarioInitFlag(0),
      diplomacyBudgetBase(0), escalationCounter(0), pendingCommitmentCost(0), pressureCounter(0),
      field900(0), turnSummaryQueue(0), missionNodeQueue(0), field910(0), aidAllocationTotal(0),
      militaryExpenses960(0) {
  // TCountry base scalars (identity strings constructed by the TCountry ctor).
  this->nationSlot = 0;
  this->encodedNationSlot = 0;
  this->treasuryValue10 = 0;
  this->field42 = 0;
  this->militaryUnitList44 = 0;
  this->homeTileIndex = 0;
  this->ownedRegionList = 0;

  int localeIndex = 0;
  if (g_pSimMgr != 0) {
    localeIndex = g_pSimMgr->difficultyLevel;
  }
  this->diplomacyBudgetBase = g_anNationBasePressureByLocale[localeIndex] * 100;
  this->escalationCounter =
      static_cast<unsigned char>(g_anGreatPowerEscalationSeedByLocale[localeIndex]);

  int nationIndex = 0;
  do {
    this->needLevelByNation[nationIndex] = 0;
    this->diplomacyPolicyByNation[nationIndex] = 0;
    this->diplomacyGrantByNation[nationIndex] = 0;
    this->needCurrentByType[nationIndex] = 0;
    this->needTargetByType[nationIndex] = 0;
    this->relationDeltaCurrent[nationIndex] = 0;
    this->relationDeltaSnapshot[nationIndex] = 0;
    this->diplomacyState1c6[nationIndex] = 0;
    this->diplomacyState1f4[nationIndex] = 0;
    this->diplomacyState222[nationIndex] = 0;
    this->diplomacyState250[nationIndex] = 0;
    this->colonyBoycottFlags[nationIndex] = 0;
    int matrixRow = 0;
    do {
      this->aidAllocationMatrix[nationIndex + matrixRow * 0x17] = 0;
      ++matrixRow;
    } while (matrixRow < 0x10);
    ++nationIndex;
  } while (nationIndex < 0x17);

  int pendingIndex = 0;
  do {
    this->serializedStatusFlags[pendingIndex] = 0;
    this->field8d6[pendingIndex] = -1;
    ++pendingIndex;
  } while (pendingIndex < 0x0D);

  int trackedIndex = 0;
  while (trackedIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[trackedIndex] = 0;
    ++trackedIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004d8bc0
void TGreatPower::RecomputeAiExpansionAndMissionPressureScores(void) {}

// FUNCTION: IMPERIALISM 0x004d8be0
void TGreatPower::RefreshTrackedEntriesAndReplanAiDevelopment(int unused) {
  (void)unused;
}

// FUNCTION: IMPERIALISM 0x004d8c00
short TGreatPower::GetDiplomacyCounterA2(void) {
  return this->diplomacyCounterA2;
}

// SYNTHETIC: IMPERIALISM 0x004d8c20
// TGreatPower::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::IGreatPower(short nationSlotIndex, short humanControlledFlag) {
  this->InitializeNationStateIdentityAndOwnedRegionList(nationSlotIndex);

  TSimMgr* localizationRuntime = g_pSimMgr;
  if (localizationRuntime != 0) {
    int runtimeIndex = localizationRuntime->difficultyLevel;
    this->treasuryValue10 = g_anNationStartingTreasuryByLocale[runtimeIndex];
  } else {
    this->treasuryValue10 = 0;
  }

  this->diplomacyEligibilityA0 = (humanControlledFlag == 1) ? 1 : 0;

  TCity* cityModel = new TCity();
  if (cityModel != 0) {
    cityModel->ICity(this);
  }
  this->city = cityModel;

  this->townMarkerList = new TSortedList();

  this->grantTotalCost = 0;
  this->needCapA6 = 0x0F;
  this->field900 = 0x0F;

  this->turnEventQueue =
      static_cast<TSortedByRelationshipList*>(TSortedByRelationshipList::CreateObject());
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->recordSize14 = 4;
  }

  this->proposalQueue =
      static_cast<TSortedByRelationshipList*>(TSortedByRelationshipList::CreateObject());
  if (this->proposalQueue != 0) {
    this->proposalQueue->recordSize14 = 4;
  }

  if (this->diplomacyEligibilityA0 != 0) {
    TForeignMinister* foreignMinister = new TForeignMinister();
    foreignMinister->IForeignMinister(this);
    this->foreignMinister = foreignMinister;

    TCityInteriorMinister* interiorMinister = new TCityInteriorMinister();
    interiorMinister->InitializeCityInteriorState(this);
    this->interiorMinister = interiorMinister;

    TDefenseMinister* defenseMinister = new TDefenseMinister();
    defenseMinister->InitializeBaseOrderArrayMetrics(this);
    this->defenseMinister = defenseMinister;
  }

  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    TSortedByRelationshipList* trackedSlotList =
        static_cast<TSortedByRelationshipList*>(TSortedByRelationshipList::CreateObject());
    if (trackedSlotList != 0) {
      trackedSlotList->recordSize14 = 0x0C;
    }
    this->diplomacyTrackedSlots[listIndex] = trackedSlotList;
    ++listIndex;
  }

  short* diplomacyNeedState = this->diplomacyPolicyByNation;
  short* diplomacyGrantState = this->diplomacyGrantByNation;
  unsigned char* diplomacyFlags = this->colonyBoycottFlags;
  int nationSlot = 0;
  while (nationSlot < kNationSlotCount) {
    diplomacyNeedState[nationSlot] = -1;
    diplomacyGrantState[nationSlot] = -1;
    diplomacyFlags[nationSlot] = 0;
    ++nationSlot;
  }

  this->trackedObjectList = new TSortedList();

  int candidateIndex = 0;
  while (candidateIndex < kNationSlotCount) {
    this->candidateNationFlags[candidateIndex] = 0;
    ++candidateIndex;
  }
  this->scenarioInitFlag = 0;
  this->field904 = 1;

  this->turnSummaryQueue =
      static_cast<TSortedByRelationshipList*>(TSortedByRelationshipList::CreateObject());
  if (this->turnSummaryQueue != 0) {
    this->turnSummaryQueue->recordSize14 = 8;
  }

  this->missionNodeQueue = new TSortedList();
  this->militaryExpenses960 = 0;
}

// FUNCTION: IMPERIALISM 0x004d9160
void TGreatPower::Free(void) {
  if (this->city != 0) {
    this->city->Free();
  }
  this->city = 0;
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->ReleasePtrList();
  }
  this->turnEventQueue = 0;
  if (this->proposalQueue != 0) {
    this->proposalQueue->ReleasePtrList();
  }
  this->proposalQueue = 0;
  if (this->foreignMinister != 0) {
    this->foreignMinister->Free();
  }
  this->foreignMinister = 0;
  if (this->interiorMinister != 0) {
    this->interiorMinister->Free();
  }
  this->interiorMinister = 0;
  if (this->defenseMinister != 0) {
    this->defenseMinister->Free();
  }
  this->defenseMinister = 0;
  TSortedByRelationshipList** trackedSlots = this->diplomacyTrackedSlots;
  int trackedSlotCount = 0x11;
  do {
    if (*trackedSlots != 0) {
      (*trackedSlots)->ReleasePtrList();
    }
    *trackedSlots = 0;
    ++trackedSlots;
    trackedSlotCount = trackedSlotCount + -1;
  } while (trackedSlotCount != 0);
  if (this->townMarkerList != 0) {
    this->townMarkerList->FreePayloadsAndDestroy();
  }
  this->townMarkerList = 0;
  if (this->trackedObjectList != 0) {
    this->trackedObjectList->FreePayloadsAndDestroy();
  }
  this->trackedObjectList = 0;
  if (this->turnSummaryQueue != 0) {
    this->turnSummaryQueue->ReleasePtrList();
  }
  this->turnSummaryQueue = 0;
  if (this->missionNodeQueue != 0) {
    this->missionNodeQueue->FreePayloadsAndDestroy();
  }
  this->missionNodeQueue = 0;
  if (this->militaryUnitList44 != 0) {
    this->militaryUnitList44->FreePayloadsAndDestroy();
  }
  this->militaryUnitList44 = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Free();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d92e0
void TGreatPower::ReadFrom(TStream* stream) {
  TCountry::ReadFrom(stream);
  stream->ReadBytes(&this->diplomacyEligibilityA0, 1);
  stream->ReadBytes(&this->diplomacyCounterA2, 2);
  stream->ReadBytes(&this->tradeCapacity, 2);
  stream->ReadBytes(&this->needCapA6, 2);
  stream->ReadBytes(&this->needsOverCapFlag, 2);
  if (g_nSaveFormatVersion < 0x3E) {
    stream->ReadBytes(&this->grantTotalCost, 2);
  } else {
    stream->ReadBytes(&this->grantTotalCost, 4);
  }
  stream->ReadBytes(&this->diplomacyCounterB0, 2);
  stream->ReadBytes(this->diplomacyPolicyByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyPolicyByNation, kNationSlotCount);
  stream->ReadBytes(this->diplomacyGrantByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyGrantByNation, kNationSlotCount);
  stream->ReadBytes(this->needCurrentByType, 0x2E);
  SwapShortArrayBytes(this->needCurrentByType, kNationSlotCount);
  stream->ReadBytes(this->needTargetByType, 0x2E);
  SwapShortArrayBytes(this->needTargetByType, kNationSlotCount);
  stream->ReadBytes(this->relationDeltaCurrent, 0x2E);
  SwapShortArrayBytes(this->relationDeltaCurrent, kNationSlotCount);
  stream->ReadBytes(this->relationDeltaSnapshot, 0x2E);
  SwapShortArrayBytes(this->relationDeltaSnapshot, kNationSlotCount);
  stream->ReadBytes(this->diplomacyState1c6, 0x2E);
  SwapShortArrayBytes(this->diplomacyState1c6, kNationSlotCount);

  if (g_nSaveFormatVersion >= 0x17) {
    stream->ReadBytes(this->diplomacyState1f4, 0x2E);
    SwapShortArrayBytes(this->diplomacyState1f4, kNationSlotCount);
  }

  stream->ReadBytes(this->diplomacyState222, 0x2E);
  SwapShortArrayBytes(this->diplomacyState222, kNationSlotCount);
  stream->ReadBytes(this->diplomacyState250, 0x2E);
  SwapShortArrayBytes(this->diplomacyState250, kNationSlotCount);

  stream->ReadBytes(&this->budgetPoolBase, 4);
  stream->ReadBytes(&this->budgetPoolDelta, 4);
  stream->ReadBytes(this->aidAllocationMatrix, 0x5C0);
  ReverseDwordArrayBytes(this->aidAllocationMatrix, 0x170);

  stream->ReadBytes(this->serializedStatusFlags, 0x0D);
  stream->ReadBytes(this->field8d6, 0x1A);
  SwapShortArrayBytes(this->field8d6, 0x0D);

  this->turnEventQueue->ReadFrom(stream);
  this->proposalQueue->ReadFrom(stream);
  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[listIndex]->ReadFrom(stream);
    ++listIndex;
  }

  if (g_nSaveFormatVersion < 0x1D) {
    if (this->encodedNationSlot == -1) {
      bool gate = this->IsRemote();
      if (gate == 0) {
        this->foreignMinister->ReadFrom(stream);
        this->interiorMinister->ReadFrom(stream);
        this->defenseMinister->ReadFrom(stream);
      }
      this->city->ReadFrom(stream);
    } else {
      if (this->foreignMinister != 0) {
        this->foreignMinister->Free();
        this->foreignMinister = 0;
      }
      if (this->interiorMinister != 0) {
        this->interiorMinister->Free();
        this->interiorMinister = 0;
      }
      if (this->defenseMinister != 0) {
        this->defenseMinister->Free();
        this->defenseMinister = 0;
      }
      if (this->city != 0) {
        this->city->Free();
        this->city = 0;
      }
    }
  } else {
    int ministerMask = stream->ReadInteger();

    if ((ministerMask & 1) == 0) {
      if (this->foreignMinister != 0) {
        this->foreignMinister->Free();
        this->foreignMinister = 0;
      }
    } else {
      TMinister* foreignMinister = this->foreignMinister;
      if (foreignMinister == 0) {
        TForeignMinister* created = new TForeignMinister();
        created->IForeignMinister(this);
        this->foreignMinister = created;
        foreignMinister = created;
      }
      if (foreignMinister != 0) {
        foreignMinister->ReadFrom(stream);
      }
    }

    if ((ministerMask & 2) == 0) {
      if (this->interiorMinister != 0) {
        this->interiorMinister->Free();
        this->interiorMinister = 0;
      }
    } else {
      TMinister* interiorMinister = this->interiorMinister;
      if (interiorMinister == 0) {
        TCityInteriorMinister* created = new TCityInteriorMinister();
        created->InitializeCityInteriorState(this);
        this->interiorMinister = created;
        interiorMinister = created;
      }
      if (interiorMinister != 0) {
        interiorMinister->ReadFrom(stream);
      }
    }

    if ((ministerMask & 4) == 0) {
      if (this->defenseMinister != 0) {
        this->defenseMinister->Free();
        this->defenseMinister = 0;
      }
    } else {
      TMinister* defenseMinister = this->defenseMinister;
      if (defenseMinister == 0) {
        TDefenseMinister* created = new TDefenseMinister();
        created->InitializeBaseOrderArrayMetrics(this);
        this->defenseMinister = created;
        defenseMinister = created;
      }
      if (defenseMinister != 0) {
        defenseMinister->ReadFrom(stream);
      }
    }

    if ((ministerMask & 8) == 0) {
      if (this->city != 0) {
        this->city->Free();
        this->city = 0;
      }
    } else {
      TCity* cityObject = this->city;
      if (cityObject != 0) {
        cityObject->ReadFrom(stream);
      }
    }
  }

  TSortedList* townMarkerList = this->townMarkerList;
  int hasItems = townMarkerList->GetCount();
  if (hasItems != 0) {
    townMarkerList->FreePayloads();
  }
  townMarkerList->ReadFrom(stream);

  int townCount = 0;
  stream->ReadBytes(&townCount, 4);

  if (townCount > 0) {
    int townOrdinal = 1;
    while (townOrdinal <= townCount) {
      TTown* townMarker = new TTown();
      if (townMarker != 0) {
        townMarker->ReadFrom(stream);
        townMarkerList->AddTail(townMarker);
      }
      ++townOrdinal;
    }
  }

  if (townCount > 0) {
    this->city->SetSelectedTownMarker(townMarkerList->GetEntryByOrdinal());
  }

  TSortedList* trackedObjectList = this->trackedObjectList;
  hasItems = trackedObjectList->GetCount();
  if (hasItems != 0) {
    trackedObjectList->FreePayloads();
  }
  trackedObjectList->ReadFrom(stream);

  int unusedOrderCount = 0;
  stream->ReadBytes(&unusedOrderCount, 4);

  int orderOrdinal = 1;
  while (orderOrdinal < 5) {
    TCivUnit* civOrderObj = new TCivUnit();
    if (civOrderObj != nullptr) {
      civOrderObj->ICivUnit(kCivilianUnitMiner, -1, this->nationSlot);
      civOrderObj->ReadFrom(stream);
    }
    ++orderOrdinal;
  }

  stream->ReadBytes(&this->diplomacyBudgetBase, 4);
  stream->ReadBytes(&this->escalationCounter, 1);
  stream->ReadBytes(&this->pendingCommitmentCost, 4);
  stream->ReadBytes(&this->pressureCounter, 1);
  stream->ReadBytes(&this->field900, 4);
  stream->ReadBytes(&this->field904, 1);

  if (g_nSaveFormatVersion > 0x0E) {
    TSortedList* missionNodeQueue = this->missionNodeQueue;
    missionNodeQueue->ReadFrom(stream);

    int nodeCount = 0;
    stream->ReadBytes(&nodeCount, 4);
    if (nodeCount > 0) {
      int nodeOrdinal = 1;
      while (nodeOrdinal <= nodeCount) {
        unsigned char hasNode = 0;
        char markerOk = stream->ReadByte(&hasNode);
        if (markerOk != 0) {
          missionNodeQueue->AddTail(0);
        }
        ++nodeOrdinal;
      }
    }
  }

  if (g_nSaveFormatVersion >= 0x26) {
    stream->ReadBytes(&this->field910, 4);
    stream->ReadBytes(&this->aidAllocationTotal, 4);
  }
  if (g_nSaveFormatVersion > 0x2F) {
    stream->ReadBytes(this->colonyBoycottFlags, kNationSlotCount);
  }
  if (g_nSaveFormatVersion > 0x34) {
    stream->ReadBytes(&this->militaryExpenses960, 4);
  }
}

// FUNCTION: IMPERIALISM 0x004d9c70
void TGreatPower::WriteTo(TStream* stream) {
  TCountry::WriteTo(stream);

  stream->WriteBytesSlot78(&this->diplomacyEligibilityA0, 1);
  stream->WriteBytesSlot78(&this->diplomacyCounterA2, 2);
  stream->WriteBytesSlot78(&this->tradeCapacity, 2);
  stream->WriteBytesSlot78(&this->needCapA6, 2);
  stream->WriteBytesSlot78(&this->needsOverCapFlag, 2);
  stream->WriteBytesSlot78(&this->grantTotalCost, 4);
  stream->WriteBytesSlot78(&this->diplomacyCounterB0, 2);

  WriteShortArrayElems(stream, this->diplomacyPolicyByNation, 0x17);
  WriteShortArrayElems(stream, this->diplomacyGrantByNation, 0x17);
  WriteShortArrayElems(stream, this->needCurrentByType, 0x17);
  WriteShortArrayElems(stream, this->needTargetByType, 0x17);
  WriteShortArrayElems(stream, this->relationDeltaCurrent, 0x17);
  WriteShortArrayElems(stream, this->relationDeltaSnapshot, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState1c6, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState1f4, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState222, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState250, 0x17);

  stream->WriteBytesSlot78(&this->budgetPoolBase, 4);
  stream->WriteBytesSlot78(&this->budgetPoolDelta, 4);
  WriteIntArrayElems(stream, this->aidAllocationMatrix, 0x170);

  stream->WriteBytesSlot78(&this->serializedStatusFlags[0], 0xd);
  WriteShortArrayElemsRev(stream, this->field8d6, 0xd);

  this->turnEventQueue->WriteTo(stream);
  this->proposalQueue->WriteTo(stream);
  for (int slotIndex = 0; slotIndex < kDiplomacyTrackedSlotCount; ++slotIndex) {
    this->diplomacyTrackedSlots[slotIndex]->WriteTo(stream);
  }

  unsigned char presenceFlags = 0;
  if (this->foreignMinister != 0) {
    presenceFlags = 1;
  }
  if (this->interiorMinister != 0) {
    presenceFlags = static_cast<unsigned char>(presenceFlags | 2);
  }
  if (this->defenseMinister != 0) {
    presenceFlags = static_cast<unsigned char>(presenceFlags | 4);
  }
  if (this->city != 0) {
    presenceFlags = static_cast<unsigned char>(presenceFlags | 8);
  }
  stream->streamSlot7c(presenceFlags);
  if (this->foreignMinister != 0) {
    this->foreignMinister->WriteTo(stream);
  }
  if (this->interiorMinister != 0) {
    this->interiorMinister->WriteTo(stream);
  }
  if (this->defenseMinister != 0) {
    this->defenseMinister->WriteTo(stream);
  }
  if (this->city != 0) {
    this->city->WriteTo(stream);
  }

  // Written out per-list (not via WriteTrackedListToStream): the original re-reads the
  // member field for every list operation instead of caching the pointer in a register,
  // and its entry count lives in the dead `stream` argument stack slot.
  this->townMarkerList->WriteTo(stream);
  {
    int entryCount = this->townMarkerList->GetCount();
    stream->WriteBytesSlot78(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      TUnit* entry = static_cast<TUnit*>(this->townMarkerList->GetEntryByOrdinal(ordinal));
      entry->WriteTo(stream);
    }
  }
  this->trackedObjectList->WriteTo(stream);
  {
    int entryCount = this->trackedObjectList->GetCount();
    stream->WriteBytesSlot78(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      TUnit* entry = static_cast<TUnit*>(this->trackedObjectList->GetEntryByOrdinal(ordinal));
      entry->WriteTo(stream);
    }
  }

  stream->WriteBytesSlot78(this->candidateNationFlags, 0x17);
  stream->WriteBytesSlot78(&this->diplomacyBudgetBase, 4);
  stream->WriteBytesSlot78(&this->escalationCounter, 1);
  stream->WriteBytesSlot78(&this->pendingCommitmentCost, 4);
  stream->WriteBytesSlot78(&this->pressureCounter, 1);
  stream->WriteBytesSlot78(&this->field900, 4);
  stream->WriteBytesSlot78(&this->field904, 1);

  this->missionNodeQueue->WriteTo(stream);
  int missionNodeCount = this->missionNodeQueue->GetCount();
  stream->WriteBytesSlot78(&missionNodeCount, 4);
  for (int nodeOrdinal = 1; nodeOrdinal <= missionNodeCount; ++nodeOrdinal) {
    void* node = this->missionNodeQueue->GetEntryByOrdinal(nodeOrdinal);
    stream->WriteObjectSlotB4(node, 0);
  }

  stream->WriteBytesSlot78(&this->field910, 4);
  stream->WriteBytesSlot78(&this->aidAllocationTotal, 4);
  stream->WriteBytesSlot78(this->colonyBoycottFlags, 0x17);
  stream->WriteBytesSlot78(&this->militaryExpenses960, 4);
}

// FUNCTION: IMPERIALISM 0x004da3e0
void TGreatPower::ReadCoreFieldsFromStream(TStream* stream, int unusedArg) {
  TCountry::ReadCoreFieldsFromStream(stream, unusedArg);

  if (this->trackedObjectList->GetCount() != 0) {
    this->trackedObjectList->FreePayloads();
  }
  this->trackedObjectList->ReadFrom(stream);

  int orderCount = stream->ReadShort();
  for (; orderCount > 0; --orderCount) {
    TCivUnit* civOrder = new TCivUnit();
    civOrder->ICivUnit(kCivilianUnitMiner, -1, this->nationSlot);
    civOrder->ReadFrom(stream);
  }
}

// --- Slot 0x0a/0x0b stream serialization pair and status-flag slots 0x2b-0x33 ---

// FUNCTION: IMPERIALISM 0x004da500
void TGreatPower::WriteCoreFieldsToStream(TStream* stream) {
  TCountry::WriteCoreFieldsToStream(stream);

  this->trackedObjectList->WriteTo(stream);
  int orderCount = this->trackedObjectList->GetCount();
  stream->WriteCountSlot88(orderCount);
  for (int ordinal = 1; ordinal <= orderCount; ++ordinal) {
    TUnit* order = static_cast<TUnit*>(this->trackedObjectList->GetEntryByOrdinal(ordinal));
    order->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x004da5c0
void TGreatPower::NoOpNationPendingActionHook(void) {}

// FUNCTION: IMPERIALISM 0x004da5e0
void TGreatPower::DispatchPendingStatusPrompts(void) {
  signed char* flags = this->serializedStatusFlags;
  char flag5Handled = (flags[5]) >= 0x33;
  if (!flag5Handled &&
      g_pCityOrderCapabilityState->orderCapRows277[this->nationSlot].techStatusByTechId[0x0f] ==
          2) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(5, this->field8d6[5]);
  }
  if (flags[6] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(6, this->field8d6[6]);
  }
  if (flags[7] == 0x32) {
    if (this->field8d6[7] == 2) {
      TCity* cityPtr = this->city;
      cityPtr->cityStockPaperCA = cityPtr->cityStockPaperCA + 10;
      cityPtr->VerifyStocks();
      g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(7, this->field8d6[7]);
    } else if (this->field8d6[7] == 3) {
      TCity* cityPtr = this->city;
      cityPtr->cityStockPaperCA = cityPtr->cityStockPaperCA + 10;
      cityPtr->VerifyStocks();
      g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(7, -1);
    }
  }
  if (flags[8] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(8, this->field8d6[8]);
  }
  if (flags[9] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(9, this->field8d6[9]);
  }
  if (flags[10] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(10, this->field8d6[10]);
  }
  if (flags[11] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(11, this->field8d6[11]);
  }
  if (flags[12] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(12, this->field8d6[12]);
  }
  if (flags[0] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(
        0, g_pCityOrderCapabilityState->activeZoneIndex1d4);
  }
  if (flags[1] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(1, this->field8d6[1]);
  }
  if (flags[2] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(2, this->field8d6[2]);
  }
  if (flags[3] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(3, this->field8d6[3]);
  }
  if (flags[4] == 0x32) {
    g_pUiRuntimeContext->QueueTurnStatusPromptSlot3C(4, this->field8d6[4]);
  }
}

// FUNCTION: IMPERIALISM 0x004da860
void TGreatPower::MarkStatusFlag5HandledIfCapabilityActive(void) {
  if (g_pCityOrderCapabilityState->orderCapRows277[this->nationSlot].techStatusByTechId[0x0f] ==
      2) {
    this->serializedStatusFlags[5] = 0x33;
  }
}

// FUNCTION: IMPERIALISM 0x004da8a0
void TGreatPower::MarkAllPendingStatusFlagsHandled(void) {
  signed char* flags = this->serializedStatusFlags;
  char flag5Handled = (flags[5]) >= 0x33;
  if (!flag5Handled &&
      g_pCityOrderCapabilityState->orderCapRows277[this->nationSlot].techStatusByTechId[0x0f] ==
          2) {
    flags[5] = 0x33;
  }
  if (flags[6] == 0x32) {
    flags[6] = 0x33;
  }
  if (flags[7] == 0x32) {
    if (this->field8d6[7] == 2) {
      flags[7] = 0x33;
    } else if (this->field8d6[7] == 3) {
      flags[7] = 0x34;
      this->field8d6[7] = -1;
    }
  }
  if (flags[8] == 0x32) {
    flags[8] = 0x33;
  }
  if (flags[9] == 0x32) {
    flags[9] = 0x33;
  }
  if (flags[10] == 0x32) {
    flags[10] = 0x33;
  }
  if (flags[11] == 0x32) {
    flags[11] = 0x33;
  }
  if (flags[12] == 0x32) {
    flags[12] = 0x33;
  }
  if (flags[0] == 0x32) {
    flags[0] = static_cast<unsigned char>(static_cast<char>(this->field8d6[0]) + 0x33);
  }
  if (flags[1] == 0x32) {
    flags[1] = static_cast<unsigned char>(static_cast<char>(this->field8d6[1]) + 0x33);
  }
  if (flags[2] == 0x32) {
    flags[2] = 0x33;
  }
  if (flags[3] == 0x32) {
    flags[3] = 0;
  }
  if (flags[4] == 0x32) {
    flags[4] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004daa10
void TGreatPower::SetNationPendingActionStateAndPayload(int index, short payload) {
  if (g_nSaveFormatVersion != -3) {
    this->serializedStatusFlags[index] = 0x32;
    this->field8d6[index] = payload;
  }
}

// FUNCTION: IMPERIALISM 0x004daa50
void TGreatPower::AddTurnStartEvent(TTurnStartEvent* event) {
  this->missionNodeQueue->AddTail(event);
}

// FUNCTION: IMPERIALISM 0x004daa80
void TGreatPower::DispatchMissionNodeCallbacksAndClearQueue(void) {
  CIterator nodeIter(this->missionNodeQueue);
  for (TMission* node = static_cast<TMission*>(nodeIter.Reset()); nodeIter.More();
       node = static_cast<TMission*>(nodeIter.Advance())) {
    node->IsANoBrainer();
  }
  this->missionNodeQueue->FreePayloads();
}

// FUNCTION: IMPERIALISM 0x004dab00
void TGreatPower::NoOpNationQueuedOrderHook(void) {}

// FUNCTION: IMPERIALISM 0x004dab20
void TGreatPower::ExecuteNationPendingActionStateMachine(void) {
  TCity* cityPtr = this->city;
  cityPtr->ProduceUnits();

  short nationSlot = this->nationSlot;

  // Land recruit order (serializedStatusFlags[1] == '2').
  if (this->serializedStatusFlags[1] == 0x32) {
    TMilitaryUnit* militaryOrder = new TMilitaryUnit();
    int nodeContext = this->GetHomeRegionCityRecordIndex();
    short capValue = g_pCityOrderCapabilityState->nationCapRows1e8[nationSlot].slots[9];
    militaryOrder->IMilitaryUnit(capValue, nodeContext, nationSlot);
    this->DispatchTurnOrderActionSlotB0(3, capValue, 1);
  }

  // Navy primary/secondary order (serializedStatusFlags[0] == '2').
  if (this->serializedStatusFlags[0] == 0x32) {
    short zoneIndex = g_pCityOrderCapabilityState->activeZoneIndex1d4;
    TZone* portZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nationSlot);
    TShip* primaryOrder =
        CreateNavyPrimaryOrderNodeAndAssignDisplayName(zoneIndex, portZone, nationSlot, 0);

    ++cityPtr->orderCountByType5c[g_pCityOrderCapabilityState->activeZoneIndex1d4];

    TAdmiral* secondaryNode = new TAdmiral(nationSlot);
    secondaryNode->AssignToShip(primaryOrder);

    this->DispatchTurnOrderActionSlotB0(3, 0x2508, 1);
    this->DispatchTurnOrderActionSlotB0(0, g_pCityOrderCapabilityState->activeZoneIndex1d4, 1);
  }

  // Civil work order (serializedStatusFlags[2] < '3').
  if (this->serializedStatusFlags[2] < 0x33) {
    bool needsCivOrder = false;
    TMinor** minorEntry = g_apMinorNationCapabilityObjects;
    short zoneCursor = 7;
    do {
      if (g_pDiplomacyTurnStateManager
              ->relationStandingScoreMatrix79c[zoneCursor + nationSlot * kNationSlotCount] > 0xa9) {
        TMinor* minor = *minorEntry;
        if (minor != 0) {
          short ownerTag = minor->encodedNationSlot;
          if (ownerTag > 99 && ownerTag < 200 && static_cast<short>(ownerTag - 100) == nationSlot) {
            goto nextMinorEntry;
          }
        }
        needsCivOrder = true;
      }
    nextMinorEntry:
      ++minorEntry;
      ++zoneCursor;
    } while (minorEntry <= &g_apMinorNationCapabilityObjects[15]);

    if (needsCivOrder) {
      TCivUnit* civOrder = new TCivUnit();
      civOrder->ICivUnit(
          kCivilianUnitDeveloper,
          g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(this->homeTileIndex, 0),
          nationSlot);
      this->SetNationPendingActionStateAndPayload(2, -1);
    }
  }

  // Final pending-action flush (serializedStatusFlags[0x0a] == '2').
  if (this->serializedStatusFlags[0x0a] == 0x32) {
    this->city->orderCountByType5c[6] += 2; // navy secondary-order counter
    this->DispatchTurnOrderActionSlotB0(1, 6, 2);
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}

// FUNCTION: IMPERIALISM 0x004dae70
char TGreatPower::HasDeveloper(void) {
  char found = 0;
  CIterator orderIter(this->trackedObjectList);
  TUnit* order = static_cast<TUnit*>(orderIter.Reset());
  if (orderIter.More()) {
    while (order->orderType != EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
      order = static_cast<TUnit*>(orderIter.Advance());
      if (!orderIter.More()) {
        return 0;
      }
    }
    found = 1;
  }
  return found;
}

// FUNCTION: IMPERIALISM 0x004daf00
void TGreatPower::SorryYouLose(void) {
  g_pUiRuntimeContext->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
}

// FUNCTION: IMPERIALISM 0x004daf30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  static const short kNationPriorityOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                                               0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (this->IsRemote() != 0) {
    return;
  }

  TSimMgr* localizationRuntime = g_pSimMgr;
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->difficultyLevel;
  }
  int compileThreshold = g_anGreatPowerCompileThresholdByLocale[localeIndex];
  if (compileThreshold > static_cast<int>(this->pressureCounter)) {
    return;
  }

  int relationDeltaByNation[0x17];
  for (int idx = 0; idx < 0x17; ++idx) {
    relationDeltaByNation[idx] = 0;
  }

  CString summaryMessageRef;

  int interactionScore = 0;

  const short* nationCursor = kNationPriorityOrder;
  while (*nationCursor != -1) {
    if (interactionScore + this->treasuryValue10 >= 0) {
      break;
    }

    short nationSlot = *nationCursor;
    TCity* cityPtr = this->city;
    if (cityPtr == 0) {
      ++nationCursor;
      continue;
    }

    short* relationDeltaPtr = (&cityPtr->cityStockCottonB6) + nationSlot;
    short relationDelta = *relationDeltaPtr;
    if (relationDelta > 0) {
      *relationDeltaPtr = 0;
      relationDeltaByNation[nationSlot] = static_cast<int>(relationDelta);

      cityPtr->VerifyStocks();

      TTradeMgr* nationInteractionState = g_pNationInteractionStateManager;
      if (nationInteractionState != 0) {
        interactionScore = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(nationSlot);
      }
    }

    ++nationCursor;
  }

  this->AddToTreasury(0);

  if (interactionScore > 0) {
    CString scoreHeaderRef;
    CString scoreTextRef;
    if (localizationRuntime != 0) {
      localizationRuntime->GetString(0x274b, 0, &scoreHeaderRef);
      localizationRuntime->GetString(0x274b, static_cast<short>(interactionScore), &scoreTextRef);
    }
    g_pUiRuntimeContext->ModalMessage(scoreTextRef, g_ptGreatPowerModalMessage, 2, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004db380
char TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TSimMgr* localizationRuntime = g_pSimMgr;
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->difficultyLevel;
  }

  int treasuryValue10 = this->treasuryValue10;
  int basePressure = this->SumAidAllocationMatrixAllCells();
  basePressure += static_cast<int>(this->needTargetByType[0x16]) * 200;
  basePressure += static_cast<int>(this->needTargetByType[0x15]) * 500;
  basePressure += this->budgetPoolBase;
  int pressureFloor = g_anNationBasePressureByLocale[localeIndex];
  if (basePressure < pressureFloor) {
    basePressure = pressureFloor;
  }

  int smoothedPressure = (this->diplomacyBudgetBase * 0x5A + basePressure * 1000) / 100;
  this->diplomacyBudgetBase = smoothedPressure;
  int pressureBand = smoothedPressure / 100;

  if (treasuryValue10 < 0) {
    int halfBand = pressureBand / 2;
    if ((-halfBand == treasuryValue10) || (-treasuryValue10 < halfBand)) {
      this->pressureCounter = 1;
    } else if ((-pressureBand == treasuryValue10) || (-treasuryValue10 < pressureBand)) {
      if (this->pressureCounter > 1) {
        int nextPressureValue =
            this->escalationCounter +
            static_cast<signed char>(g_anGreatPowerPressureRiseStepByLocale[localeIndex]);
        int pressureRiseCap = g_anGreatPowerPressureRiseCapByLocale[localeIndex];
        if (nextPressureValue > pressureRiseCap) {
          nextPressureValue = pressureRiseCap;
        }
        this->escalationCounter = static_cast<signed char>(nextPressureValue);
      }
      this->pressureCounter = 2;
    } else {
      CString sharedMessageRef;
      int nextPressureValue =
          this->escalationCounter +
          static_cast<signed char>(g_anGreatPowerPressureRiseStepByLocale[localeIndex]);
      int pressureRiseCap = g_anGreatPowerPressureRiseCapByLocale[localeIndex];
      if (nextPressureValue > pressureRiseCap) {
        nextPressureValue = pressureRiseCap;
      }
      this->escalationCounter = static_cast<signed char>(nextPressureValue);

      if (this->pressureCounter < 3) {
        this->pressureCounter = 3;
      } else {
        this->pressureCounter = static_cast<signed char>(this->pressureCounter + 1);
      }

      int pressureTier = static_cast<int>(this->pressureCounter);
      int hardThreshold = g_anGreatPowerPressureHardAlertThresholdByLocale[localeIndex];
      int compileThreshold = g_anGreatPowerCompileThresholdByLocale[localeIndex];

      if (hardThreshold <= pressureTier) {
        g_pSimMgr->GetString(0x274b, 4, &sharedMessageRef);
        g_pUiRuntimeContext->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
        return 1;
      }

      if (pressureTier >= compileThreshold) {
        g_pSimMgr->GetString(0x274b, 1, &sharedMessageRef);
        g_pUiRuntimeContext->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
        // 0x004db5f6: the original re-runs the relationship-delta compile here.
        this->CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage();
      } else {
        int statusId = (pressureTier == (compileThreshold - 1)) ? 3 : 2;
        g_pSimMgr->GetString(0x274b, static_cast<short>(statusId), &sharedMessageRef);
        g_pUiRuntimeContext->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
      }
    }
  } else {
    if (this->pressureCounter != 0) {
      int nextPressureValue =
          this->escalationCounter -
          static_cast<signed char>(g_anGreatPowerPressureDecayStepByLocale[localeIndex]);
      int pressureMinFloor = g_anGreatPowerPressureMinFloorByLocale[localeIndex];
      if (nextPressureValue < pressureMinFloor) {
        nextPressureValue = pressureMinFloor;
      }
      this->escalationCounter = static_cast<signed char>(nextPressureValue);
      this->pressureCounter = 0;
    }
  }

  treasuryValue10 = this->treasuryValue10;
  if (treasuryValue10 >= 0) {
    this->field900 = 0;
    return 0;
  }

  int drainAmount = (0xC7 - static_cast<int>(this->escalationCounter) * treasuryValue10) / 200;
  this->field900 = drainAmount;
  this->treasuryValue10 = treasuryValue10 - drainAmount;
  return 0;
}
