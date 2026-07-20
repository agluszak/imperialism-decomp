// TGreatPower — nation-state object for the seven playable great powers
// (Mac source: UCountry.cpp / UCountryAuto.cpp). Manual decompilation file;
// reccmp pairs bodies by the FUNCTION address markers.

#include <math.h>
#include <stddef.h>
#include <string.h>

#include "decomp_types.h"
#include <stdlib.h>

#include "game/CIterator.h"
#include "game/CString.h"
#include "game/GameAssert.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/nation_slot_eligibility.h"
#include "game/nation_stream_serialization.h"
#include "game/quickdraw_rendering.h"
#include "game/TCity.h"
#include "game/TPopulationMgr.h"
#include "game/TCityInteriorMinister.h"
#include "game/TCivUnit.h"
#include "game/TCountry.h"
#include "game/TDefendProvinceMission.h"
#include "game/TDefenseMinister.h"
#include "game/TDiplomacyMgr.h"
#include "game/TForeignMinister.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/THelpMgr.h"
#include "game/TNewsMgr.h"
#include "game/TMinister.h"
#include "game/TMilitaryUnit.h"
#include "game/TProvinceDesirabilityList.h"
#include "game/TMinor.h"
#include "game/TMission.h"
#include "game/TMultiplayerMgr.h"
#include "game/TNationInteractionStateManager.h"
#include "game/TNavyMgr.h"
#include "game/TNavyMission.h"
#include "game/TObject.h"
#include "game/TOcean.h"
#include "game/TProductionOrder.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TSimMgr.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TSortedList.h"
#include "game/TStream.h"
#include "game/TTown.h"
#include "game/TTurnInstructionCiviCursor.h"
#include "game/TUiRuntimeContext.h"
#include "game/TUnit.h"
#include "game/turn_flow_cooldown.h"
#include "game/TViewMgr.h"
#include "game/TZone.h"
#include "game/ui_invalidation_guard.h"
#include "game/UiRuntimeContext.h"

// Autogen-stub externs (Hard Rule 9: generic thunk declaration + typed cast at
// the callsite). Retire each by porting the real body.
undefined4 BuildCityInfluenceLevelMap(void); // 0x004dbbb0
undefined4 RebuildMinorNationDispositionLookupTables(void);

// Real body ported at 0x005b7f50 (file end, ascending-address order). Genuine __stdcall
// predicate: returns 1 when the resource index is in [13,16].
char __stdcall IsSpecialNationInteractionResource(short resourceIndex);

// Real body ported in TMission.cpp (0x00535940).
TMission* __cdecl FindFirstTrackedHandlerMatchingModeAndShortKey(TSortedList* list, int kind,
                                                                 short key, int mode);

static const int kMapNodeCount = 0x180;
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kMajorNationCount = 7;
static const int kDiplomacyTrackedSlotCount = 0x11;

static const float kOne = 1.0f;

// Packed entry layout shared by the diplomacyTrackedSlots queues
// (slots 0x6c/0x6d/0x6e/0x6f/0x70).
struct TrackedSlotEntryPacket {
  short kind;
  short targetNation;
  short value;
  short eligibility;
  int payload;
};

// C++98-compatible compile-time layout guards for the known TGreatPower core block.
// NOTE: class size/shape is still evolving. A failing guard is a useful drift signal,
// not automatically a correctness bug, unless it breaks a proven-stable core contract.
#define TG_LAYOUT_ASSERT(name, expr) typedef char name[(expr) ? 1 : -1]
TG_LAYOUT_ASSERT(TGreatPower_Offset_nationSlot_0x0C, offsetof(TGreatPower, nationSlot) == 0x0C);
TG_LAYOUT_ASSERT(TGreatPower_Offset_homeRegionIndex_0x88,
                 offsetof(TGreatPower, homeRegionIndex) == 0x88);
TG_LAYOUT_ASSERT(TGreatPower_Offset_ownedRegionList_0x90,
                 offsetof(TGreatPower, ownedRegionList) == 0x90);
TG_LAYOUT_ASSERT(TGreatPower_Offset_diplomacyPolicyByNation_0xB2,
                 offsetof(TGreatPower, diplomacyPolicyByNation) == 0xB2);
TG_LAYOUT_ASSERT(TGreatPower_Offset_aidAllocationMatrix_0x280,
                 offsetof(TGreatPower, aidAllocationMatrix) == 0x280);
TG_LAYOUT_ASSERT(TGreatPower_Offset_city_0x894, offsetof(TGreatPower, city) == 0x894);
TG_LAYOUT_ASSERT(TGreatPower_Size_Exactly_0x964, sizeof(TGreatPower) == 0x964);
#undef TG_LAYOUT_ASSERT

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
      pendingAidTotal(0) {
  // TCountry base scalars (identity strings constructed by the TCountry ctor).
  this->nationSlot = 0;
  this->encodedNationSlot = 0;
  this->treasuryValue10 = 0;
  this->field42 = 0;
  this->militaryUnitList44 = 0;
  this->homeRegionIndex = 0;
  this->ownedRegionList = 0;

  int localeIndex = 0;
  if (g_pSimMgr != 0) {
    localeIndex = g_pSimMgr->redrawEnabled;
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

TGreatPower::TGreatPower(int arg1, int arg2) {
  InitializeNationStateRuntimeSubsystems(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004d8bc0
void TGreatPower::NoOpTailStateHookSlot2B4(void) {}

// FUNCTION: IMPERIALISM 0x004d8be0
void TGreatPower::NoOpTailStateHookSlot2B8(int arg) {
  (void)arg;
}

// SYNTHETIC: IMPERIALISM 0x004d8c20
// TGreatPower::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004d8c50
TGreatPower::~TGreatPower() {}

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  this->InitializeNationStateIdentityAndOwnedRegionList(static_cast<short>(arg1));

  TSimMgr* localizationRuntime = g_pSimMgr;
  if (localizationRuntime != 0) {
    int runtimeIndex = localizationRuntime->redrawEnabled;
    this->treasuryValue10 = g_anNationStartingTreasuryByLocale[runtimeIndex];
  } else {
    this->treasuryValue10 = 0;
  }

  this->diplomacyEligibilityA0 = (static_cast<short>(arg2) == 1) ? 1 : 0;

  TCity* cityModel = new TCity();
  if (cityModel != 0) {
    cityModel->InitializeCityProductionState(arg1);
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
    foreignMinister->InitializeStateAndCounters(this);
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
  this->pendingAidTotal = 0;
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
      char gate = this->ShouldDispatchImmediatelySlot28();
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
        created->InitializeStateAndCounters(this);
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
      civOrderObj->InitializeCivWorkOrderState(0, -1, this->nationSlot);
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
    stream->ReadBytes(&this->pendingAidTotal, 4);
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
      TUnit* entry = reinterpret_cast<TUnit*>(this->townMarkerList->GetEntryByOrdinal(ordinal));
      entry->WriteTo(stream);
    }
  }
  this->trackedObjectList->WriteTo(stream);
  {
    int entryCount = this->trackedObjectList->GetCount();
    stream->WriteBytesSlot78(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      TUnit* entry = reinterpret_cast<TUnit*>(this->trackedObjectList->GetEntryByOrdinal(ordinal));
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
  stream->WriteBytesSlot78(&this->pendingAidTotal, 4);
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
    civOrder->InitializeCivWorkOrderState(0, -1, this->nationSlot);
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
void TGreatPower::AddNodeToMissionNodeQueue(void* node) {
  this->missionNodeQueue->AddTail(node);
}

// FUNCTION: IMPERIALISM 0x004daa80
void TGreatPower::DispatchMissionNodeCallbacksAndClearQueue(void) {
  CIterator nodeIter(this->missionNodeQueue);
  for (TMission* node = static_cast<TMission*>(nodeIter.Reset()); nodeIter.More();
       node = static_cast<TMission*>(nodeIter.Advance())) {
    node->DispatchMissionNodeSlot28();
  }
  this->missionNodeQueue->FreePayloads();
}

// FUNCTION: IMPERIALISM 0x004dab00
void TGreatPower::NoOpNationQueuedOrderHook(void) {}

// FUNCTION: IMPERIALISM 0x004dae70
char TGreatPower::HasTrackedOrderOfType7(void) {
  char found = 0;
  CIterator orderIter(this->trackedObjectList);
  TUnit* order = static_cast<TUnit*>(orderIter.Reset());
  if (orderIter.More()) {
    while (order->orderType != 7) {
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
void TGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004daf30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  static const short kNationPriorityOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                                               0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (this->ShouldDispatchImmediatelySlot28() != 0) {
    return;
  }

  TSimMgr* localizationRuntime = g_pSimMgr;
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->redrawEnabled;
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

  this->AddToNationMetricAtField10(0);

  if (interactionScore > 0) {
    CString scoreHeaderRef;
    CString scoreTextRef;
    if (localizationRuntime != 0) {
      localizationRuntime->GetString(0x274b, 0, &scoreHeaderRef);
      localizationRuntime->GetString(0x274b, static_cast<short>(interactionScore), &scoreTextRef);
    }
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
        scoreTextRef, &g_cstrGreatPowerPressureMessage, 2, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004db380
char TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TSimMgr* localizationRuntime = g_pSimMgr;
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->redrawEnabled;
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
        int nextPressureValue = static_cast<int>(this->escalationCounter) +
                                static_cast<int>(static_cast<signed char>(
                                    g_anGreatPowerPressureRiseStepByLocale[localeIndex]));
        int pressureRiseCap = g_anGreatPowerPressureRiseCapByLocale[localeIndex];
        if (nextPressureValue > pressureRiseCap) {
          nextPressureValue = pressureRiseCap;
        }
        this->escalationCounter = static_cast<signed char>(nextPressureValue);
      }
      this->pressureCounter = 2;
    } else {
      CString sharedMessageRef;
      int nextPressureValue = static_cast<int>(this->escalationCounter) +
                              static_cast<int>(static_cast<signed char>(
                                  g_anGreatPowerPressureRiseStepByLocale[localeIndex]));
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
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            sharedMessageRef, &g_cstrGreatPowerPressureMessage, 2, 0);
        return 1;
      }

      if (pressureTier >= compileThreshold) {
        g_pSimMgr->GetString(0x274b, 1, &sharedMessageRef);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            sharedMessageRef, &g_cstrGreatPowerPressureMessage, 2, 0);
        // 0x004db5f6: the original re-runs the relationship-delta compile here.
        this->CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage();
      } else {
        int statusId = (pressureTier == (compileThreshold - 1)) ? 3 : 2;
        g_pSimMgr->GetString(0x274b, static_cast<short>(statusId), &sharedMessageRef);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            sharedMessageRef, &g_cstrGreatPowerPressureMessage, 2, 0);
      }
    }
  } else {
    if (this->pressureCounter != 0) {
      int nextPressureValue = static_cast<int>(this->escalationCounter) -
                              static_cast<int>(static_cast<signed char>(
                                  g_anGreatPowerPressureDecayStepByLocale[localeIndex]));
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

// FUNCTION: IMPERIALISM 0x004db7d0
void TGreatPower::BuildTransportLinkedInfluenceMap(char** outInfluenceMap) {
  if (this->city == 0) {
    return;
  }
  char* influenceMap = new char[0x1950];
  if (influenceMap == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szUCountrySourcePath_00696728, 0xa0e);
  }
  memset(influenceMap, 0, 0x1950);

  CIterator markerCursor(this->townMarkerList);
  TTown* marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0 &&
         static_cast<int>(marker->regionId14) != this->homeRegionIndex) {
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  int homeLinked = marker->IsTransportLinkedAndEnabled();
  if (homeLinked == 0) {
    this->MarkConnectedOwnedRegionsFrom(reinterpret_cast<unsigned char*>(influenceMap),
                                        marker->regionId14);
    marker = static_cast<TTown*>(markerCursor.Reset());
    while (markerCursor.More() != 0 && homeLinked == 0) {
      if (influenceMap[marker->regionId14] != 0 && marker->IsTransportLinkedAndEnabled() != 0) {
        homeLinked = 1;
      }
      marker = static_cast<TTown*>(markerCursor.Advance());
    }
  }
  marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if (marker->IsTransportLinkedAndEnabled() != 0 && homeLinked != 0 &&
        marker->activeFlag4f != 0 && influenceMap[marker->regionId14] == 0) {
      this->MarkConnectedOwnedRegionsFrom(reinterpret_cast<unsigned char*>(influenceMap),
                                          marker->regionId14);
    }
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if ((influenceMap[marker->regionId14] == 0 || marker->activeFlag4f == 0) &&
        (marker->IsTransportLinkedAndEnabled() == 0 || homeLinked == 0)) {
      marker->transportLinkedFlag4c = 0;
    } else {
      marker->transportLinkedFlag4c = 1;
    }
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  if (outInfluenceMap != 0) {
    marker = static_cast<TTown*>(markerCursor.Reset());
    while (markerCursor.More() != 0) {
      if (marker->IsTransportLinkedAndEnabled() != 0 && homeLinked != 0) {
        influenceMap[marker->regionId14] = 1;
      }
      marker = static_cast<TTown*>(markerCursor.Advance());
    }
    *outInfluenceMap = influenceMap;
    return;
  }
  delete[] influenceMap;
}

// --- Slots 0x35/0x37/0x50/0x51/0x55-0x57 ---

// FUNCTION: IMPERIALISM 0x004dbac0
void TGreatPower::MarkConnectedOwnedRegionsFrom(unsigned char* regionMap, short regionId) {
  short nextRegion;
  do {
    regionMap[regionId] = 1;
    nextRegion = 0;
    char adjacencyBits = g_pGlobalMapState->terrainStateTable[regionId].adjacencyBits06;
    for (short direction = 0; direction < 6; ++direction) {
      if ((adjacencyBits & (1 << direction)) != 0) {
        short neighbor = TMapMgr::GetWrappedHexNeighborTileIndexByDirection(regionId, direction);
        if (static_cast<short>(g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04) ==
                this->nationSlot &&
            regionMap[neighbor] == 0) {
          if (nextRegion != 0) {
            this->MarkConnectedOwnedRegionsFrom(regionMap, neighbor);
          } else {
            nextRegion = neighbor;
          }
        }
      }
    }
    regionId = nextRegion;
  } while (nextRegion != 0 && regionMap[nextRegion] == 0);
}

// FUNCTION: IMPERIALISM 0x004dbd20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  const int kMapRegionSlotCount = 0x1950;

  short* currentNeedByType = this->needCurrentByType;
  short* developmentByType = &this->needCurrentByType[7]; // +0x11c overlays this runtime array.
  short* targetNeedByType = this->needTargetByType;
  short& controlledRegionCount = this->needCurrentByType[0x13]; // +0x134
  // 0x004dbbb0 is still an autogen stub; Hard Rule 9 thunk call until ported.
  char* influenceByRegion = reinterpret_cast<char*>(BuildCityInfluenceLevelMap());
  TMapMgr* globalMapState = g_pGlobalMapState;
  int regionIndex = 0;

  for (int i = 0; i < kNationSlotCount; ++i) {
    currentNeedByType[i] = 0;
  }
  controlledRegionCount = 0;

  if (influenceByRegion != 0 && globalMapState != 0 && globalMapState->terrainStateTable != 0 &&
      globalMapState->cityScoreTable != 0) {
    TTerrainStateRecordView* terrainTable = globalMapState->terrainStateTable;
    TGlobalMapCityScoreRecord* cityTable = globalMapState->cityScoreTable;
    while (static_cast<short>(regionIndex) < kMapRegionSlotCount) {
      char influence = *influenceByRegion;
      if (influence != 0) {
        TTerrainStateRecordView* terrainRecord = &terrainTable[regionIndex];
        if (terrainRecord->gateFlag == 0) {
          if (influence == 2) {
            ++controlledRegionCount;
          }
        } else {
          for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
            short resourceType = static_cast<short>(terrainRecord->resourceTypeByEdge[edgeIndex]);
            if (resourceType != -1) {
              char contribution = globalMapState->CallMetricSlotC4(regionIndex, edgeIndex);
              currentNeedByType[resourceType] = static_cast<short>(
                  currentNeedByType[resourceType] + static_cast<short>(contribution));
            }
          }

          if (terrainRecord->roadFlag != 0 && influence == 2) {
            ++controlledRegionCount;
          }

          int cityIndex = static_cast<int>(terrainRecord->cityRecordIndex);
          TGlobalMapCityScoreRecord* cityRecord = &cityTable[cityIndex];
          if (cityRecord->cityTileIndex04 == static_cast<short>(regionIndex)) {
            for (int devIdx = 0; devIdx < 10; ++devIdx) {
              developmentByType[devIdx] = static_cast<short>(
                  developmentByType[devIdx] + cityRecord->resourceDevelopmentCounts82[devIdx]);
            }
          }
        }
      }

      ++regionIndex;
      ++influenceByRegion;
    }
  }

  for (int typeIndex = 0; typeIndex < kNationSlotCount; ++typeIndex) {
    if (currentNeedByType[typeIndex] < targetNeedByType[typeIndex]) {
      this->UpdateNeedTargetAndAccumulateOverCap(typeIndex, currentNeedByType[typeIndex]);
    }
  }
}

// Advances per-region development counters and emits diplomacy/map events when stage changes.

// FUNCTION: IMPERIALISM 0x004dbf00
void TGreatPower::AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void) {
  TLongintList* regionList = this->ownedRegionList;
  if (regionList == 0) {
    return;
  }

  int totalRegions = regionList->GetSize();
  int regionOrdinal = 1;
  while (regionOrdinal <= totalRegions) {
    short regionId = static_cast<short>(regionList->At(regionOrdinal));
    unsigned char pendingStage = 0;
    unsigned char needsRedraw = 0;

    TMapMgr* globalMapState = g_pGlobalMapState;
    TSimMgr* localizationRuntime = g_pSimMgr;
    if (globalMapState != 0 && localizationRuntime != 0 && globalMapState->cityScoreTable != 0 &&
        globalMapState->terrainStateTable != 0) {
      TGlobalMapCityScoreRecord* cityTable = globalMapState->cityScoreTable;
      TTerrainStateRecordView* terrainTable = globalMapState->terrainStateTable;
      TGlobalMapCityScoreRecord* cityRecord = cityTable + regionId;
      short homeRegionId = static_cast<short>(this->homeRegionIndex);
      if (cityRecord->cityTileIndex04 != homeRegionId) {
        unsigned int turnDelta =
            static_cast<unsigned int>(static_cast<int>(localizationRuntime->GetTurnTickSlot3C()) -
                                      static_cast<int>(cityRecord->lastTurnTick));

        if (turnDelta > 4) {
          int resourceSums[kNationSlotCount];
          int i = 0;
          while (i < kNationSlotCount) {
            resourceSums[i] = 0;
            ++i;
          }

          int linkedCount = cityRecord->linkedRegionCount;
          int linkedIndex = 0;
          while (linkedIndex < linkedCount) {
            short linkedRegion = cityRecord->linkedRegionIds[linkedIndex];
            int edge = 0;
            while (edge < 2) {
              signed char resourceType = terrainTable[linkedRegion].resourceTypeByEdge[edge];
              if (resourceType != -1) {
                resourceSums[resourceType] +=
                    static_cast<int>(globalMapState->CallMetricSlotC4(linkedRegion, edge));
              }
              ++edge;
            }
            ++linkedIndex;
          }

          short* stage1CounterA = &cityRecord->resourceDevelopmentCounts82[1];
          short* stage1CounterB = &cityRecord->resourceDevelopmentCounts82[2];
          short* stage1CounterC = &cityRecord->resourceDevelopmentCounts82[4];
          short* stage1CounterD = &cityRecord->resourceDevelopmentCounts82[5];
          short* stage2CounterA = &cityRecord->resourceDevelopmentCounts82[6];
          short* stage2CounterB = &cityRecord->resourceDevelopmentCounts82[7];
          short* stage2CounterC = &cityRecord->resourceDevelopmentCounts82[8];

          if ((turnDelta & 1U) == 0) {
            int sum01 = resourceSums[0] + resourceSums[1];
            if (sum01 != 0) {
              int prod = this->city->GetBuildingType(1);
              int limit = (static_cast<int>(*stage1CounterA) +
                           ((static_cast<int>(*stage1CounterA) >> 0x1f) & 3U)) >>
                          2;
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (limit < prodLimit && static_cast<int>(*stage1CounterA) < sum01 / 2) {
                pendingStage = 1;
                *stage1CounterA = static_cast<short>(*stage1CounterA + 1);
                needsRedraw = 1;
              }
            }

            if (resourceSums[2] != 0) {
              int prod = this->city->GetBuildingType(5);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterB) < prodLimit &&
                  static_cast<int>(*stage1CounterB) < resourceSums[2] / 2) {
                pendingStage = 1;
                *stage1CounterB = static_cast<short>(*stage1CounterB + 1);
                needsRedraw = 1;
              }
            }

            if (resourceSums[3] != 0) {
              int prod = this->city->GetBuildingType(3);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterC) < prodLimit &&
                  static_cast<int>(*stage1CounterC) < resourceSums[3] / 2) {
                pendingStage = 1;
                *stage1CounterC = static_cast<short>(*stage1CounterC + 1);
                needsRedraw = 1;
              }
            }

            TTechMgr* orderCapabilityState = g_pCityOrderCapabilityState;
            int capabilityScore = this->city->GetBuildingType(7);
            if (capabilityScore != 0 && orderCapabilityState != 0 &&
                orderCapabilityState->hasProductionOrder193 != 0) {
              if (static_cast<int>(*stage1CounterD) < capabilityScore / 2) {
                pendingStage = 1;
                *stage1CounterD = static_cast<short>(*stage1CounterD + 1);
                needsRedraw = 1;
              }
            }
          }

          if (turnDelta > 9 && (turnDelta & 1U) != 0) {
            this->GetDiplomacyCounterA2();

            if (*stage1CounterA != 0 &&
                static_cast<int>(*stage2CounterA) < static_cast<int>(*stage1CounterA) / 2) {
              pendingStage = 2;
              *stage2CounterA = static_cast<short>(*stage2CounterA + 1);
              needsRedraw = 1;
            }
            if (*stage1CounterB != 0 &&
                static_cast<int>(*stage2CounterB) < static_cast<int>(*stage1CounterB) / 2) {
              pendingStage = 2;
              *stage2CounterB = static_cast<short>(*stage2CounterB + 1);
              needsRedraw = 1;
            }
            if (*stage1CounterC != 0 &&
                static_cast<int>(*stage2CounterC) < static_cast<int>(*stage1CounterC) / 2) {
              pendingStage = 2;
              *stage2CounterC = static_cast<short>(*stage2CounterC + 1);
              needsRedraw = 1;
            }
          }

          if (cityRecord->developmentStage < pendingStage) {
            g_pGlobalMapState->SetRegionDevelopmentStageByte(regionId, pendingStage);
            if (pendingStage == 2) {
              this->SetNationPendingActionStateAndPayload(4, regionId);
            } else {
              this->SetNationPendingActionStateAndPayload(3, regionId);
              if (this->expansionAlertCounter < 0x33) {
                this->SetNationPendingActionStateAndPayload(8, -1);
              }
            }
          }
        }

        if (localizationRuntime->redrawEnabled != 0 && needsRedraw != 0) {
          g_pGameFlowState->DispatchCityRedrawInvalidateEvent(regionId);
        }
      }
    }

    ++regionOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x004dc3f0
char TGreatPower::AnyNeedCurrentExceedsTargetWhenCapMismatch(void) {
  char result = 0;
  if (this->needCapA6 != this->needsOverCapFlag) {
    short needIndex = 0;
    while (this->needCurrentByType[needIndex] <= this->needTargetByType[needIndex]) {
      ++needIndex;
      if (needIndex > 0x16) {
        return result;
      }
    }
    result = 1;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004dc440
char TGreatPower::HasAnyCommodityRecordBelowStepValue(void) {
  TCity* tradeCity = this->city;
  if (tradeCity->productionSummary1d8->stockLevel1c <= 1) {
    return 0;
  }
  for (int recordIndex = 8; recordIndex < 0xd; ++recordIndex) {
    TProductionOrder* record =
        this->city->tradeCommodityRecordPtrs[static_cast<short>(recordIndex)];
    short controlValue = record->quantityField04;
    if (record->MaxOrder() > controlValue) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004dc4c0
short TGreatPower::ComputeTreasuryStatusPromptCode(void) {
  int dispatchCounter = g_pDiplomacyTurnStateManager->proposalDispatchCounter790;
  short promptCode = 0;
  int turnTick = g_pSimMgr->GetTurnTickSlot3C();
  if (dispatchCounter == 0 && turnTick == 3) {
    promptCode = 0x25;
    return promptCode;
  }
  if (dispatchCounter - turnTick > 4 && this->treasuryValue10 >= 10000) {
    promptCode = 0x27;
  }
  return promptCode;
}

// FUNCTION: IMPERIALISM 0x004dc540
char TGreatPower::CompareMissionScoreVariantsByMode(int mode) {
  if (mode == 0) {
    int nodeContext = this->GetHomeRegionCityRecordIndex();
    float localScore = TDefendProvinceMission::ComputeLocalSupportVectorScore(nodeContext);
    float crossNationScore =
        TDefendProvinceMission::ComputeCrossNationSupportVectorScore(nodeContext);
    if (localScore < crossNationScore) {
      return 0;
    }
    return 1;
  } else {
    TZone* portZoneContext =
        g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(this->nationSlot);

    if (portZoneContext->PrimaryZoneHeapCapacity() <= 0) {
      void* resizedEntries = realloc(portZoneContext->PrimaryZoneHeapData(), 8);
      if (resizedEntries == 0) {
        resizedEntries = realloc(portZoneContext->PrimaryZoneHeapData(), 4);
        portZoneContext->PrimaryZoneHeapData() = static_cast<TZone**>(resizedEntries);
        portZoneContext->PrimaryZoneHeapCapacity() = 1;
      } else {
        portZoneContext->PrimaryZoneHeapData() = static_cast<TZone**>(resizedEntries);
        portZoneContext->PrimaryZoneHeapCapacity() = 2;
      }
    }
    if (portZoneContext->PrimaryZoneHeapSize() <= 0) {
      portZoneContext->PrimaryZoneHeapSize() = 1;
    }

    TZone* firstEntry = portZoneContext->PrimaryZoneHeapData()[0];

    float exactSourceScore =
        TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(this->nationSlot,
                                                                                  firstEntry);
    float diplomacyFilteredScore =
        TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(this->nationSlot,
                                                                                 firstEntry);
    if (exactSourceScore < diplomacyFilteredScore) {
      return 0;
    }
    return 1;
  }
}

// FUNCTION: IMPERIALISM 0x004dc660
char TGreatPower::BuildGreatPowerMapContextTriggeredNationEventMessages(CString* outMessageText) {
  char anyMessage = 0;
  char found = 0;
  int nationSlot;
  for (nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationSlot, this->nationSlot) !=
            0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      found = 1;
    }
    if (found != 0) {
      break;
    }
  }
  if (found != 0) {
    TZone* contextEntry = g_pMapActionContextListHead;
    while (contextEntry != 0) {
      contextEntry->GetContextOrdinalOrInvalid();
      found = 0;
      // The original dispatches this on the context node (ecx = contextEntry at
      // 0x004dc6e2), not on the nation object.
      if (contextEntry->HasSecondaryNeighborWithNationTag(this->nationSlot) != 0) {
        short candidate;
        for (candidate = 0; candidate < 7; ++candidate) {
          if (candidate != this->nationSlot &&
              g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                      candidate) != 0) {
            unsigned char candidateMask = static_cast<unsigned char>(1 << candidate);
            if ((contextEntry->nationKeyMask10 & candidateMask) != 0) {
              unsigned char selfMask = static_cast<unsigned char>(1 << this->nationSlot);
              if ((contextEntry->nationKeyMask10 & selfMask) == 0) {
                CString zoneName;
                contextEntry->AssignZoneDisplayNameToOutputRef(&zoneName);
                *outMessageText += "\n     " + zoneName;
                anyMessage = 1;
                found = 1;
              }
            }
          }
          if (found != 0) {
            break;
          }
        }
      }
      contextEntry = contextEntry->prev18;
    }
  }
  return anyMessage;
}

// FUNCTION: IMPERIALISM 0x004dc840
char TGreatPower::BuildGreatPowerEligibleNationEventMessagesFromLinkedList(
    CString* outMessageText) {
  char found = 0;
  char anyMessage = 0;
  int nationSlot;
  for (nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationSlot, this->nationSlot) !=
            0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      found = 1;
    }
    if (found != 0) {
      break;
    }
  }
  if (found != 0) {
    CIterator cursor(townMarkerList);
    TTown* town = static_cast<TTown*>(cursor.Reset());
    while (cursor.More()) {
      if (town->enabledFlag4d != 0 && town->transportLinkedFlag4c == 0) {
        anyMessage = 1;
        CString townName;
        g_pGlobalMapState->AssignCityRecordDisplayName(
            g_pGlobalMapState->terrainStateTable[town->regionId14].cityRecordIndex, &townName);
        *outMessageText += "\n     " + townName;
      }
      town = static_cast<TTown*>(cursor.Advance());
    }
  }
  return anyMessage;
}

// FUNCTION: IMPERIALISM 0x004dc9f0
void TGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  if (this->city == 0) {
    return;
  }

  this->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  this->AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents();
  this->ApplyNationResourceNeedTargetsToOrderState();
  this->CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage();
  this->city->EndCityPhase();
  this->NoOpNationPendingActionHook();
}

// FUNCTION: IMPERIALISM 0x004dca60
void TGreatPower::NotifyCitySlot2C(void) {
  TCity* cityPtr = this->city;
  if (cityPtr != 0) {
    cityPtr->PredictedNeeds();
  }
}

// FUNCTION: IMPERIALISM 0x004dca80
void TGreatPower::OrphanRetStub_004dca80(int) {}

// FUNCTION: IMPERIALISM 0x004dcaa0
unsigned int TGreatPower::GetEffectiveDiplomacyCounterA2ForCode(int proposalCode) {
  if (this->foreignMinister->capabilityFlag26 != 0) {
    if (g_pNationInteractionStateManager->IsCapabilityCategoryActiveSlot3C(4) != 0) {
      if (static_cast<short>(proposalCode) == 4) {
        return static_cast<unsigned short>(this->diplomacyCounterA2);
      }
      short resolvedCode =
          g_pNationInteractionStateManager->ResolveProposalCodeForCategorySlot84(proposalCode, 4);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      return static_cast<unsigned short>(this->diplomacyCounterA2);
    }
  }
  if (this->foreignMinister->capabilityFlag28 != 0) {
    if (g_pNationInteractionStateManager->IsCapabilityCategoryActiveSlot3C(5) != 0) {
      if (static_cast<short>(proposalCode) == 5) {
        return static_cast<unsigned short>(this->diplomacyCounterA2);
      }
      short resolvedCode =
          g_pNationInteractionStateManager->ResolveProposalCodeForCategorySlot84(proposalCode, 5);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      return static_cast<unsigned short>(this->diplomacyCounterA2);
    }
  }
  if (this->foreignMinister->capabilityFlag24 != 0 &&
      g_pNationInteractionStateManager->IsCapabilityCategoryActiveSlot3C(3) != 0) {
    if (static_cast<short>(proposalCode) != 3) {
      short resolvedCode =
          g_pNationInteractionStateManager->ResolveProposalCodeForCategorySlot84(proposalCode, 3);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      if (static_cast<short>(proposalCode) != 3) {
        return static_cast<unsigned short>(this->diplomacyCounterA2);
      }
    }
    if (this->foreignMinister->capabilityFlag26 != 0) {
      int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 1;
      return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
    }
  }
  return static_cast<unsigned short>(this->diplomacyCounterA2);
}

// FUNCTION: IMPERIALISM 0x004dcc30
void TGreatPower::OrphanRetStub_004dcc30(void) {}

// FUNCTION: IMPERIALISM 0x004dcc50
void TGreatPower::ApplyDiplomacyState222ToCityStockAndClear(void) {
  for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->AddToCityStockCounterAndRefresh(nationSlot, this->diplomacyState222[nationSlot]);
    this->diplomacyState222[nationSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcca0
void TGreatPower::ApplyRelationDeltaToCityStockAndUpdateState1f4(void) {
  for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->AddToCityStockCounterAndRefresh(nationSlot, this->relationDeltaCurrent[nationSlot]);
    if (this->diplomacyState250[nationSlot] == -1 && this->relationDeltaCurrent[nationSlot] == 0) {
      this->diplomacyState1f4[nationSlot] =
          static_cast<short>(this->diplomacyState1f4[nationSlot] + 1);
    } else {
      this->diplomacyState1f4[nationSlot] = 0;
    }
    this->relationDeltaCurrent[nationSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcd10
void TGreatPower::ApplyNationResourceNeedTargetsToOrderState(void) {
  this->AddToNationMetricAtField10(static_cast<int>(this->needTargetByType[0x15]) * 500);

  TCity* cityPtr = this->city;
  if (cityPtr != 0) {
    cityPtr->cityStockGemsE0 = 0;
    cityPtr->VerifyStocks();
  }

  this->AddToNationMetricAtField10(static_cast<int>(this->needTargetByType[0x16]) * 200);

  if (cityPtr != 0) {
    cityPtr->cityStockGoldE2 = 0;
    cityPtr->VerifyStocks();
  }

  for (int needIndex = 0; static_cast<short>(needIndex) < kNationSlotCount; ++needIndex) {
    this->AddToCityStockCounterAndRefresh(static_cast<short>(needIndex),
                                          this->needTargetByType[needIndex]);
  }
}

// FUNCTION: IMPERIALISM 0x004dcdd0
void TGreatPower::UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value) {
  short* target = &this->needTargetByType[needIndex];
  this->needsOverCapFlag = static_cast<short>(this->needsOverCapFlag + (value - *target));
  *target = value;
}

// FUNCTION: IMPERIALISM 0x004dce10
void TGreatPower::SetNationResourceNeedCurrentByType(int needType, int currentValue) {
  short needIndex = static_cast<short>(needType);
  this->needCurrentByType[needIndex] = static_cast<short>(currentValue);
}

// FUNCTION: IMPERIALISM 0x004dce40
bool TGreatPower::IsNeedTargetEqualCurrent(short needIndex) {
  bool result = false;
  if (this->needTargetByType[needIndex] == this->needCurrentByType[needIndex]) {
    result = true;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004dce70
short TGreatPower::GetNeedTargetByType(short needIndex) {
  return this->needTargetByType[needIndex];
}

// FUNCTION: IMPERIALISM 0x004dce90
void TGreatPower::TryIncrementNationResourceNeedTargetTowardCurrent(int needType) {
  short needIndex = static_cast<short>(needType);
  short targetValue = this->needTargetByType[needIndex];
  short currentValue = this->needCurrentByType[needIndex];
  if (targetValue < currentValue) {
    this->UpdateNeedTargetAndAccumulateOverCap(needType, static_cast<int>(targetValue) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004dcf10
void TGreatPower::IsNationResourceNeedCurrentSumExceedingCapA6(void) {
  int sumCurrentNeeds = 0;
  for (int needIndex = 0; needIndex < kNationSlotCount; ++needIndex) {
    sumCurrentNeeds += static_cast<int>(this->needCurrentByType[needIndex]);
  }

  this->needsOverCapFlag = (sumCurrentNeeds > static_cast<int>(this->needCapA6)) ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x004dcf60
short TGreatPower::TryDecayRelationNeedScores9AndB(void) {
  if (this->GetDiplomacyExternalStateByTarget(9) != 0) {
    if (this->GetDiplomacyExternalStateByTarget(0xb) != 0) {
      this->AddToCityStockCounterAndRefresh(9, -1);
      this->AddToCityStockCounterAndRefresh(0xb, -1);
      this->needCapA6 = static_cast<short>(this->needCapA6 + 1);
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004dcfd0
short TGreatPower::TryDecayRelationNeedScores9And8(void) {
  if (this->GetDiplomacyExternalStateByTarget(9) > 2) {
    if (this->GetDiplomacyExternalStateByTarget(8) != 0) {
      this->AddToCityStockCounterAndRefresh(9, -3);
      this->AddToCityStockCounterAndRefresh(8, -1);
      this->tradeCapacity = static_cast<short>(this->tradeCapacity + 1);
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004dd040
void TGreatPower::ResetDiplomacyLevelForNationSlot12(NationSlot targetNationSlot, int resetLevel) {
  short nation = static_cast<short>(targetNationSlot);
  if (nation != this->nationSlot &&
      static_cast<short>(resetLevel) != this->needLevelByNation[nation]) {
    this->needLevelByNation[nation] = static_cast<short>(resetLevel);
  }
  if (this->diplomacyEligibilityA0 != 0) {
    g_pHelpMgr->NoOpDiplomacyPolicyStateChangedHook(-1, targetNationSlot, 1);
  }
  if (resetLevel == 300) {
    this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004dd0c0
void TGreatPower::SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
    int targetNationSlot, int isBoycottEnabled) {
  unsigned char boycottFlag = static_cast<unsigned char>(isBoycottEnabled);
  int policyValue = ((-(int)(boycottFlag != 0)) & 0xC8) + 0x64;
  this->colonyBoycottFlags[targetNationSlot] = boycottFlag;

  for (int secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    char hasNationFlag = secondaryState->HasMinorStandingLinkSlot5C(this->nationSlot);
    if (hasNationFlag != 0) {
      secondaryState->SetDiplomacyStandingSlot48(targetNationSlot, policyValue);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd140
void TGreatPower::RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void) {
  int total = 0;
  for (int resourceType = 0; resourceType < 0x0E; ++resourceType) {
    short resourceWeight = GetResourceDescriptorWeightWord0ByType(static_cast<short>(resourceType));
    short orderCount = this->city->orderCountByType5c[resourceType];
    total += static_cast<short>(resourceWeight * orderCount);
  }

  this->tradeCapacity = static_cast<short>(total);
  this->diplomacyCounterA2 = static_cast<short>(total);
}

// FUNCTION: IMPERIALISM 0x004dd1b0
void TGreatPower::ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  this->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();

  this->diplomacyCounterB0 = 0;
  this->budgetPoolDelta = 0;
  this->budgetPoolBase = 0;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    short snapshotValue = this->diplomacyState250[nationIndex];
    if (snapshotValue == -1) {
      ++this->diplomacyCounterB0;
    }
    this->diplomacyState1c6[nationIndex] = snapshotValue;

    short needScore = this->GetDiplomacyExternalStateByTarget(nationIndex);
    if (needScore < this->diplomacyState1c6[nationIndex]) {
      this->diplomacyState1c6[nationIndex] = this->GetDiplomacyExternalStateByTarget(nationIndex);
    }

    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      this->aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd270
void TGreatPower::RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    short snapshotValue = this->diplomacyState250[nationIndex];
    if (snapshotValue == -1) {
      ++this->diplomacyCounterB0;
    }
    this->diplomacyState1c6[nationIndex] = snapshotValue;

    short needScore = this->GetDiplomacyExternalStateByTarget(nationIndex);
    if (needScore < this->diplomacyState1c6[nationIndex]) {
      this->diplomacyState1c6[nationIndex] = this->GetDiplomacyExternalStateByTarget(nationIndex);
    }

    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      this->aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd310
void TGreatPower::ReleaseDiplomacyTrackedObjectSlots850(void) {
  // 0x004dd310 dispatches [vt+0x1c] (ClearAndFreeAllPtrListRecords on the list
  // vtable) on every queue, with no null check.
  for (int listIndex = 0; listIndex < kDiplomacyTrackedSlotCount; ++listIndex) {
    this->diplomacyTrackedSlots[listIndex]->ClearAndFreeAllPtrListRecords();
  }
}

// FUNCTION: IMPERIALISM 0x004dd340
void TGreatPower::AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                             short rowIndex) {
  this->AddToNationMetricAtField10(amount);
  int index =
      static_cast<int>(rowIndex) * kAidAllocationColumnCount + static_cast<int>(columnIndex);
  this->aidAllocationMatrix[index] += amount;
  this->aidAllocationTotal += amount;
}

// FUNCTION: IMPERIALISM 0x004dd3b0
int TGreatPower::SumAidAllocationMatrixColumnForTarget(short targetNationId) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int matrixIndex = rowIndex * kAidAllocationColumnCount + static_cast<int>(targetNationId);
    total += this->aidAllocationMatrix[matrixIndex];
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd3f0
int TGreatPower::SumAidAllocationMatrixAllCells(void) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int columnIndex = 0;
    while (columnIndex < kAidAllocationColumnCount) {
      int matrixIndex = rowIndex * kAidAllocationColumnCount + columnIndex;
      total += this->aidAllocationMatrix[matrixIndex];
      ++columnIndex;
    }
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd430
int TGreatPower::ComputeRemainingDiplomacyAidBudget(void) {
  int outstandingCommitments = this->pendingCommitmentCost;
  int pendingAdjustments = this->pendingAidTotal;
  int baseBudget = this->SumAidAllocationMatrixAllCells();
  return baseBudget + this->budgetPoolBase + this->budgetPoolDelta - pendingAdjustments -
         outstandingCommitments;
}

// FUNCTION: IMPERIALISM 0x004dd470
void TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  TSimMgr* localizationTable = g_pSimMgr;
  if (localizationTable->redrawEnabled != 0 || localizationTable->mode != 2) {
    return;
  }

  this->SetDiplomacyState1c6ClampedToCounterA4(7, -1);
  this->SetDiplomacyState1c6ClampedToCounterA4(0, -1);
  this->SetDiplomacyState1c6ClampedToCounterA4(1, -1);
  this->SetDiplomacyState1c6ClampedToCounterA4(2, -1);
  this->SnapshotDiplomacyState1c6Into250();
}

// FUNCTION: IMPERIALISM 0x004dd4e0
void TGreatPower::AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void) {
  const int kNeedSlotStart = 7;
  const int kNeedSlotEndExclusive = 12;
  const int kNeedSlotFallback = 5;

  if (this->diplomacyEligibilityA0 == 0) {
    if (this->foreignMinister != 0) {
      this->foreignMinister->Call8C();
    }
    return;
  }

  TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
  bool hasUnfilledNeedSlot = false;
  for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
    if (this->QueryNationMetricBySlot7C(needSlot) < 0) {
      hasUnfilledNeedSlot = true;
    }
  }

  if (hasUnfilledNeedSlot) {
    short selectedNation = static_cast<short>(-1);
    TSortedByRelationshipList* relationshipList =
        static_cast<TSortedByRelationshipList*>(TSortedByRelationshipList::CreateObject());
    if (relationshipList != 0) {
      relationshipList->recordSize14 = 0;
    }
    if (diplomacyManager != 0 && relationshipList != 0) {
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(this->nationSlot, 1,
                                                                relationshipList);
    }

    for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
      if (this->QueryNationMetricBySlot7C(needSlot) < 0) {
        int listIndex = relationshipList->GetSize();
        if (selectedNation < 0) {
          while (listIndex >= 1) {
            short* rankedNation =
                static_cast<short*>(relationshipList->GetPtrListEntryByOneBasedIndex(listIndex));
            selectedNation = (rankedNation != 0) ? *rankedNation : static_cast<short>(-1);
            --listIndex;
            TGreatPower* candidateState = g_apNationStates[selectedNation];
            if (candidateState != 0 && candidateState->diplomacyEligibilityA0 != 0) {
              selectedNation = static_cast<short>(-1);
            }
            if (selectedNation >= 0) {
              break;
            }
          }
        }

        if (selectedNation >= 0) {
          TGreatPower* selectedNationState = g_apNationStates[selectedNation];
          if (selectedNationState != 0) {
            selectedNationState->AssignNeedSlotFromSourceSlot19C(needSlot, this->nationSlot);
          }
        }
      }
    }

    if (relationshipList != 0) {
      relationshipList->ReleasePtrList();
    }
  }

  if (this->QueryNationMetricBySlot7C(kNeedSlotFallback) == -1) {
    bool foundFallbackNation = false;
    int fallbackNationSlot = -1;
    while (!foundFallbackNation) {
      fallbackNationSlot = rand() % 7;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(fallbackNationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(fallbackNationSlot,
                                                                  this->nationSlot) == 0 &&
          fallbackNationSlot != this->nationSlot) {
        foundFallbackNation = true;
      }
    }

    TGreatPower* fallbackNationState = g_apNationStates[fallbackNationSlot];
    if (fallbackNationState != 0) {
      fallbackNationState->AssignNeedSlotFromSourceSlot19C(kNeedSlotFallback, this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd740
short TGreatPower::GetDiplomacyExternalStateByTarget(short targetNationSlot) {
  TCity* cityPtr = this->city;
  if (cityPtr == 0) {
    return 0;
  }
  return (&cityPtr->cityStockCottonB6)[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004dd770
void TGreatPower::SetCityStockCounterAndRefresh(short targetSlot, short value) {
  TCity* cityPtr = this->city;
  (&cityPtr->cityStockCottonB6)[targetSlot] = value;
  cityPtr->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004dd7b0
void TGreatPower::AddToCityStockCounterAndRefresh(short targetSlot, short value) {
  TCity* cityPtr = this->city;
  (&cityPtr->cityStockCottonB6)[targetSlot] =
      static_cast<short>((&cityPtr->cityStockCottonB6)[targetSlot] + value);
  cityPtr->VerifyStocks();
}

// FUNCTION: IMPERIALISM 0x004dd7f0
unsigned int TGreatPower::ComputeProductionMetricForOrderKind(short orderKind) {
  switch (orderKind) {
  case 0:
  case 1: {
    int production = this->city->GetBuildingType(0);
    return production + production;
  }
  case 2: {
    int production = this->city->GetBuildingType(4);
    return production + production;
  }
  case 3:
  case 4:
    return this->city->GetBuildingType(2);
  case 6: {
    int production = this->city->GetBuildingType(6);
    return production + production;
  }
  case 8: {
    int production = this->city->GetBuildingType(1);
    return production + production;
  }
  case 9:
  case 10: {
    int production = this->city->GetBuildingType(5);
    return production + production;
  }
  case 0xb: {
    int production = this->city->GetBuildingType(3);
    return production + production;
  }
  case 0xc: {
    int production = this->city->GetBuildingType(0xb);
    return production + production;
  }
  case 7: {
    short* summary = this->city->GetCitySummaryRecordSlot74();
    TCity* city = this->city;
    short available = static_cast<short>(
        ((((summary[0x14] + summary[0x12] + summary[0x11]) - city->cityStockCannedFoodC4) -
          city->cityStockLivestockDE) -
         city->cityStockGrainD8) -
        city->cityStockFruitDA);
    if (available >= 0) {
      return static_cast<unsigned short>(available);
    }
    return 0;
  }
  case 5:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x10:
    return 0;
  default:
    return orderKind;
  }
}

// FUNCTION: IMPERIALISM 0x004dda20
void TGreatPower::DecrementDiplomacyCounterA2ByValue(int delta) {
  this->diplomacyCounterA2 =
      static_cast<short>(this->diplomacyCounterA2 - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda40
void TGreatPower::DecrementDiplomacyCounterA2Slot66(int delta) {
  this->diplomacyCounterA2 =
      static_cast<short>(this->diplomacyCounterA2 - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda60
int TGreatPower::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  return this->diplomacyState1c6[nationSlot] + this->relationDeltaSnapshot[nationSlot];
}

// FUNCTION: IMPERIALISM 0x004dda90
void TGreatPower::AssignNeedSlotFromSourceSlot19C(short targetNationSlot, short sourceNationSlot) {
  TNewsMgr* queueManager = g_pInterNationEventQueueManager;
  if (queueManager != 0) {
    queueManager->QueueInterNationEventType0FWithBitmaskMerge(this->nationSlot, sourceNationSlot,
                                                              targetNationSlot, '\0');
  }
}

void TGreatPower::QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                                  short sourceNationSlot) {
  this->AssignNeedSlotFromSourceSlot19C(targetNationSlot, sourceNationSlot);
}

// FUNCTION: IMPERIALISM 0x004ddad0
char TGreatPower::AreDiplomacyState1c6Slots13To16AllNonPositive(void) {
  char result = 1;
  short nationSlot = 0xd;
  do {
    if (nationSlot > 0x10) {
      return result;
    }
    short state = this->diplomacyState1c6[nationSlot];
    if (state > 0 && this->relationDeltaSnapshot[nationSlot] + state > 0) {
      result = 0;
    }
    ++nationSlot;
  } while (result != 0);
  return result;
}

// FUNCTION: IMPERIALISM 0x004ddb20
short TGreatPower::QueryNationMetricBySlot7C(short targetNationSlot) {
  return this->diplomacyState1c6[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004ddb40
void TGreatPower::SetDiplomacyState1c6ClampedToCounterA4(short targetSlot, short value) {
  if (targetSlot != -10) {
    short clamped = this->tradeCapacity;
    if (value <= this->tradeCapacity) {
      clamped = value;
    }
    this->diplomacyState1c6[targetSlot] = clamped;
  }
}

// FUNCTION: IMPERIALISM 0x004ddb80
void TGreatPower::SnapshotDiplomacyState1c6Into250(void) {
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->diplomacyState250[nationSlot] = this->diplomacyState1c6[nationSlot];
  }
}

// FUNCTION: IMPERIALISM 0x004ddbb0
char TGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                int arg4) {
  if (this->IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(static_cast<short>(arg4)) != 0) {
    TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;
    uiRuntimeContext->DispatchDecisionSlot98(this->nationSlot, arg2, arg3, arg4);
    return 1;
  }

  this->AppendTrackedSlotEntry(1, arg1, 0, static_cast<short>(arg4), 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ddc30
void TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                 int multiplier) {
  short index = static_cast<short>(resourceIndex);
  short deltaWord = static_cast<short>(delta);
  this->relationDeltaSnapshot[index] =
      static_cast<short>(this->relationDeltaSnapshot[index] + deltaWord);

  int deltaInt = static_cast<int>(deltaWord);
  short multiplierWord = static_cast<short>(multiplier);
  int scaledDelta = static_cast<int>(multiplierWord) * deltaInt;
  this->AddToNationMetricAtField10(-scaledDelta);

  if (deltaWord > 0) {
    this->DecrementDiplomacyCounterA2Slot66(delta);
    this->budgetPoolDelta -= scaledDelta;
    return;
  }

  this->budgetPoolBase -= scaledDelta;
  if (IsSpecialNationInteractionResource(index) != 0) {
    this->field910 -= deltaInt;
  }
}

// FUNCTION: IMPERIALISM 0x004ddcf0
void TGreatPower::AddShortDeltaToNationCounterAtOffset198(short index, short delta) {
  this->relationDeltaSnapshot[index] =
      static_cast<short>(this->relationDeltaSnapshot[index] + delta);
}

// FUNCTION: IMPERIALISM 0x004ddd20
void TGreatPower::ClearDiplomacyState1c6ForTarget(short targetSlot) {
  this->diplomacyState1c6[targetSlot] = 0;
}

// FUNCTION: IMPERIALISM 0x004ddd50
bool TGreatPower::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  bool result = true;
  if (this->GetDiplomacyCounterA2() <= 0 || this->diplomacyState1c6[targetNationSlot] >= 0) {
    result = false;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004ddd90
void TGreatPower::AppendTrackedSlotEntry(short kind, int targetNation, short value, short slotIndex,
                                         int payload) {
  TrackedSlotEntryPacket packet;
  packet.payload = payload;
  packet.kind = kind;
  packet.targetNation = static_cast<short>(targetNation);
  packet.value = value;
  if (kind == 1 ||
      (kind == 0 && g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(targetNation) == 0)) {
    packet.eligibility = 1;
  } else {
    packet.eligibility = 0;
  }
  this->diplomacyTrackedSlots[slotIndex]->InsertCopiedRecordSortedByComparator(&packet);
}

// FUNCTION: IMPERIALISM 0x004dde30
char TGreatPower::AnyTrackedSlotEntryHasZeroField4(short targetSlot) {
  char found = 0;
  for (short entryIndex = 1; found == 0; ++entryIndex) {
    TSortedByRelationshipList* trackedSlot = this->diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->GetSize()) {
      return found;
    }
    TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
        trackedSlot->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->value == 0) {
      found = 1;
    }
  }
  return found;
}

// FUNCTION: IMPERIALISM 0x004dde80
short TGreatPower::GetTrackedSlotEntryCountLow(short targetSlot) {
  return static_cast<short>(this->diplomacyTrackedSlots[targetSlot]->GetSize());
}

// FUNCTION: IMPERIALISM 0x004ddeb0
void TGreatPower::ReadTrackedSlotEntryFields(short slotIndex, short ordinal, short* outKind,
                                             short* outValue, short* outTargetNation,
                                             int* outPayload) {
  TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
      this->diplomacyTrackedSlots[slotIndex]->GetPtrListEntryByOneBasedIndex(ordinal));
  *outKind = entry->kind;
  *outTargetNation = entry->targetNation;
  *outValue = entry->value;
  *outPayload = entry->payload;
}

// FUNCTION: IMPERIALISM 0x004ddf20
void TGreatPower::AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                                int payload) {
  bool matched = false;
  for (int entryIndex = 1; !matched; ++entryIndex) {
    TSortedByRelationshipList* trackedSlot = this->diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->GetSize()) {
      return;
    }
    TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
        trackedSlot->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->targetNation == matchKey) {
      matched = true;
      entry->payload = payload;
      entry->value = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ddf90
void TGreatPower::ClearDiplomacyState1c6Block(void) {
  // 0x2E-byte clear (11 dwords + 1 trailing word) — the same rep stosd/stosw
  // pair the original emits.
  memset(this->diplomacyState1c6, 0, sizeof(this->diplomacyState1c6));
}

// FUNCTION: IMPERIALISM 0x004ddfc0
bool TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                                   short policyCode) {
  const short kPolicyClear = -1;
  const short kPolicyRequiresCompatibilityStart = 0x12D;
  const short kPolicyTreasurySmall = 0x133;
  const short kPolicyTreasuryLarge = 0x134;

  char shouldApply = 1;

  if (policyCode <= kPolicyRequiresCompatibilityStart) {
    if (policyCode != kPolicyRequiresCompatibilityStart) {
      if (policyCode == kPolicyClear) {
        short previousPolicy = this->diplomacyPolicyByNation[targetClass];
        if (previousPolicy == kPolicyTreasurySmall) {
          this->AddToNationMetricAtField10(500);
        } else if (previousPolicy == kPolicyTreasuryLarge) {
          this->AddToNationMetricAtField10(5000);
        }
      }
      goto APPLY_POLICY_IF_ALLOWED;
    }
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(this->nationSlot,
                                                                          targetClass) != 2) {
      shouldApply = 0;
    }
    goto APPLY_POLICY_IF_ALLOWED;
  }

  switch (policyCode - (kPolicyRequiresCompatibilityStart + 1)) {
  case 0:
  case 1:
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(this->nationSlot,
                                                                          targetClass) != 2) {
      shouldApply = 0;
    }
    break;

  case 3: {
    TSimMgr* localizationTable = g_pSimMgr;
    if (localizationTable != 0 && localizationTable->mode == 6) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetClass, 4, -1);
    }

    TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
    short relationTier =
        g_pDiplomacyTurnStateManager->GetRelationTierSlot70(targetClass, this->nationSlot);
    if (relationTier == 2) {
      g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, targetClass, 1);
    }

    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[targetClass];
    if (terrainDescriptor != 0) {
      const TCountry* terrain = terrainDescriptor;
      short encodedNationSlot = terrain->encodedNationSlot;
      if (encodedNationSlot > 199) {
        int resolvedNationSlot = DecodeTerrainNationSlotFromDescriptor(terrain, encodedNationSlot);
        if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                    resolvedNationSlot) == 0) {
          this->ApplyDiplomacyPolicyStateForTargetWithCostChecks(resolvedNationSlot, 0x131);
        }
      }
    }

    if (this->diplomacyEligibilityA0 != 0) {
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetClass, -1);
    }
    break;
  }

  case 5:
    if (this->CanAffordAdditionalDiplomacyCostAfterCommitments(500) != 0) {
      this->AddToNationMetricAtField10(0xFFFFFE0C);
    } else {
      shouldApply = 0;
    }
    break;

  case 6:
    if (this->CanAffordAdditionalDiplomacyCostAfterCommitments(5000) != 0) {
      this->AddToNationMetricAtField10(0xFFFFEC78);
    } else {
      shouldApply = 0;
    }
    break;

  default:
    break;
  }

APPLY_POLICY_IF_ALLOWED:
  if (shouldApply) {
    this->diplomacyPolicyByNation[targetClass] = policyCode;
  }
  if (this->diplomacyEligibilityA0 != 0) {
    g_pHelpMgr->NoOpDiplomacyPolicyStateChangedHook(static_cast<int>(policyCode),
                                                    static_cast<int>(targetClass), shouldApply);
  }
  return shouldApply != 0;
}

// FUNCTION: IMPERIALISM 0x004de2b0
void TGreatPower::BeginTurnDiplomacyPrePassSlot1c8() {}

// FUNCTION: IMPERIALISM 0x004de2d0
void TGreatPower::ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void) {
  const unsigned short kResetValue = 0xFFFF;
  const unsigned short kRecurringGrantMask = 0x4000;

  int targetNation = 0;
  while (static_cast<short>(targetNation) < 0x17) {
    this->diplomacyPolicyByNation[targetNation] = static_cast<short>(kResetValue);

    unsigned short grantEntry =
        static_cast<unsigned short>(this->diplomacyGrantByNation[targetNation]);
    this->diplomacyGrantByNation[targetNation] = static_cast<short>(kResetValue);
    if (grantEntry != kResetValue && (grantEntry & kRecurringGrantMask) != 0) {
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, grantEntry);
    }

    ++targetNation;
  }
}

// FUNCTION: IMPERIALISM 0x004de340
bool TGreatPower::SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2) {
  const unsigned short kGrantClear = 0xFFFF;
  const unsigned short kGrantMask = 0x3FFF;
  const short kInfluenceAlertThreshold = 0x00FA;

  short targetNation = static_cast<short>(arg1);
  int targetIndex = static_cast<int>(targetNation);
  unsigned short oldGrantRaw =
      static_cast<unsigned short>(this->diplomacyGrantByNation[targetIndex]);
  unsigned short newGrantRaw = static_cast<unsigned short>(arg2);
  bool accepted = true;

  if (newGrantRaw != oldGrantRaw) {
    if (newGrantRaw != kGrantClear &&
        this->CanAffordDiplomacyGrantEntryForTarget(targetNation, newGrantRaw) == 0) {
      accepted = false;
    } else {
      if (oldGrantRaw != kGrantClear) {
        int oldGrantValue = static_cast<short>(oldGrantRaw & kGrantMask);
        this->grantTotalCost -= oldGrantValue;
        this->AddToNationMetricAtField10(oldGrantValue);
      }

      if (newGrantRaw != kGrantClear) {
        int newGrantValue = static_cast<short>(newGrantRaw & kGrantMask);
        this->grantTotalCost += newGrantValue;
        this->AddToNationMetricAtField10(-newGrantValue);
      }

      this->diplomacyGrantByNation[targetIndex] = static_cast<short>(newGrantRaw);
    }
  }

  if (this->diplomacyEligibilityA0 != 0) {
    g_pHelpMgr->NoOpDiplomacyPolicyStateChangedHook(
        static_cast<int>(static_cast<short>(newGrantRaw)), static_cast<int>(targetNation),
        accepted ? 1 : 0);

    if (accepted && newGrantRaw != kGrantClear && targetNation > 6) {
      bool shouldDispatchAlert = false;
      TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
      if (diplomacyManager != 0) {
        int majorNation = 0;
        while (majorNation < 7) {
          if (majorNation != this->nationSlot) {
            short relationValue =
                g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[majorNation * 0x17 + targetIndex];
            if (relationValue > kInfluenceAlertThreshold) {
              shouldDispatchAlert = true;
              break;
            }
          }
          ++majorNation;
        }
      }

      if (shouldDispatchAlert) {
        CString alertHeaderRef;
        CString alertTextRef;
        g_pSimMgr->GetString(0x2753, 0x44, &alertHeaderRef);
        g_pSimMgr->GetString(0x2753, 0x45, &alertTextRef);
        // alertHeaderRef is fetched and released without being dispatched, as in
        // the original (0x004de4a2..0x004de4ea).
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            alertTextRef, &g_cstrGreatPowerPressureMessage, 0, 0);
      }
    }
  }
  return accepted;
}

// FUNCTION: IMPERIALISM 0x004de5e0
void TGreatPower::RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(int arg1) {
  short targetNation = static_cast<short>(arg1);
  short rawGrantEntry = this->diplomacyGrantByNation[targetNation];
  int grantValue = 0;
  if (rawGrantEntry > 0) {
    grantValue = static_cast<short>(rawGrantEntry & 0x3FFF);
  }
  if (grantValue <= 0) {
    return;
  }

  g_apTerrainTypeDescriptorTable[targetNation]->AddToNationMetricAtField10(grantValue);

  this->grantTotalCost -= grantValue;

  if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(targetNation,
                                                                        this->nationSlot) != 2) {
    return;
  }

  int sourceNation = this->nationSlot;
  int relationCode = static_cast<int>(
      g_pDiplomacyTurnStateManager
          ->relationStandingScoreMatrix79c[(targetNation) * 0x17 + (sourceNation)]);
  int relationDelta;
  switch (grantValue) {
  case 1000:
    relationDelta = 2;
    break;
  case 3000:
    relationDelta = 4;
    break;
  case 5000:
    relationDelta = 6;
    break;
  case 10000:
    relationDelta = 10;
    break;
  default:
    relationDelta = 0;
    break;
  }
  g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(sourceNation, targetNation,
                                                       relationCode + relationDelta);
}

void TGreatPower::RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1) {
  this->RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(arg1);
}

// FUNCTION: IMPERIALISM 0x004de700
char TGreatPower::CanAffordDiplomacyGrantEntryForTarget(short targetNationId,
                                                        unsigned short proposedGrantEntry) {
  int proposedGrantValue = static_cast<short>(proposedGrantEntry & 0x3FFF);
  if (proposedGrantValue < 0) {
    return 1;
  }

  short currentGrantEntry = this->diplomacyGrantByNation[targetNationId];
  int currentGrant = 0;
  if (currentGrantEntry > 0) {
    currentGrant = static_cast<short>(currentGrantEntry & 0x3FFF);
  }

  int availableBudget = this->ComputeAvailableDiplomacyBudget();
  int remainingBudget = currentGrant - proposedGrantValue + availableBudget;
  char canAfford = static_cast<char>(remainingBudget >= 0);
  return canAfford;
}

// FUNCTION: IMPERIALISM 0x004de790
char TGreatPower::CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost) {
  int availableBudget = this->ComputeAvailableDiplomacyBudget();
  int remainingBudget = availableBudget - this->grantTotalCost - static_cast<int>(additionalCost);
  char canAfford = static_cast<char>(remainingBudget >= 0);
  return canAfford;
}

// FUNCTION: IMPERIALISM 0x004de7e0
void TGreatPower::ApplyTurnDiplomacyStateSlot1e0(void) {
  if (this->city != 0 && this->foreignMinister != 0) {
    this->foreignMinister->Call80();
  }
}

// FUNCTION: IMPERIALISM 0x004de810
void TGreatPower::NotifyWarResetSlotA5(void) {
  // 0x004de810: no null checks; the list is reloaded from `this` every iteration
  // and [vt+0x30] / [vt+0x1c] are dispatched directly on each payload (a
  // TUnit-family order object).
  int remaining = this->trackedObjectList->GetCount();
  if (remaining != 0) {
    do {
      TUnit* order = static_cast<TUnit*>(this->trackedObjectList->GetEntryByOrdinal(remaining));
      order->DetachUnitOrderFromOwnerAndReset();
      order->Free();
      --remaining;
    } while (remaining != 0);
  }
}

// FUNCTION: IMPERIALISM 0x004de860
void TGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers(int arg1) {
  const int kResetDiplomacyLevel = 100;
  const int kResetPolicyCode = -1;
  const int kDipFlagRelation = 6;
  const int kDipFlagPolicy = 0x31;

  if (g_pInterNationEventQueueManager != 0) {
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1D, this->nationSlot, 7,
                                                                        '\0');
  }
  reinterpret_cast<void(__cdecl*)(void)>(RebuildMinorNationDispositionLookupTables)();

  this->encodedNationSlot = static_cast<short>(arg1 + 100);

  int nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
        nationSlot != this->nationSlot && nationSlot != arg1) {
      g_apTerrainTypeDescriptorTable[nationSlot]->SetNationPercentFieldByModeAndDescriptorLinks(
          this->nationSlot, kResetDiplomacyLevel);
    }
  }

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

  this->treasuryValue10 = 0;

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

  this->diplomacyCounterA2 = 0;
  this->tradeCapacity = 0;
  this->needCapA6 = 0;
  this->needsOverCapFlag = 0;
  this->grantTotalCost = 0;
  this->diplomacyCounterB0 = 0;

  unsigned char* candidateNationFlags = this->candidateNationFlags;
  short* needLevelByNation = this->needLevelByNation;

  int idx;
  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->diplomacyPolicyByNation[idx] = static_cast<short>(-1);
    this->diplomacyGrantByNation[idx] = static_cast<short>(-1);
    candidateNationFlags[idx] = 0;
    needLevelByNation[idx] = 100;
  }

  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->needCurrentByType[idx] = 0;
    this->needTargetByType[idx] = 0;
    this->relationDeltaCurrent[idx] = 0;
    this->relationDeltaSnapshot[idx] = 0;
    this->diplomacyState1c6[idx] = 0;
    this->diplomacyState1f4[idx] = 0;
    this->diplomacyState222[idx] = 0;
    this->diplomacyState250[idx] = 0;
    int col;
    for (col = 0; col < kAidAllocationRowCount; ++col) {
      int matrixIndex = col * kAidAllocationColumnCount + idx;
      this->aidAllocationMatrix[matrixIndex] = 0;
    }
  }

  this->budgetPoolBase = 0;
  this->budgetPoolDelta = 0;

  if (this->proposalQueue != 0) {
    this->proposalQueue->ClearAndFreeAllPtrListRecords();
  }
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->ClearAndFreeAllPtrListRecords();
  }

  this->ReleaseDiplomacyTrackedObjectSlots850();

  if (this->city != 0) {
    this->city->Free();
  }
  this->city = 0;

  this->NotifyWarResetSlotA5();

  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (nationSlot != this->nationSlot &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot, nationSlot,
                                                                  kDipFlagRelation, 0);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, nationSlot,
                                                           kDipFlagPolicy);
      TGreatPower* nationState = g_apNationStates[nationSlot];
      if (nationState->diplomacyEligibilityA0 == 0) {
        nationState->NotifyActionSlot94(this->nationSlot, 0x131);
      }
      this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(nationSlot),
                                               kResetDiplomacyLevel);
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(nationSlot, kResetPolicyCode);
    }
  }

  int secondarySlot;
  for (secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    bool directReset = true;
    short encodedOwnerNation = secondaryState->encodedNationSlot;
    if (encodedOwnerNation >= 200) {
      short ownerNation = secondaryState->DecodeOwnerNationSlot();
      directReset = ownerNation == this->nationSlot;
    }

    if (!directReset) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot, secondarySlot,
                                                                  kDipFlagRelation, 0);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, secondarySlot,
                                                           kDipFlagPolicy);
    }

    this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(secondarySlot),
                                             kResetDiplomacyLevel);
    this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(secondarySlot, kResetPolicyCode);

    if (g_apTerrainTypeDescriptorTable[secondarySlot] != 0) {
      secondaryState->SetDiplomacyStandingSlot48(this->nationSlot, kResetDiplomacyLevel);
    }
  }

  if (g_pNavyOrderManager != 0) {
    g_pNavyOrderManager->RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(
        this->nationSlot);
  }
  g_pGlobalMapState->ApplyJoinEmpireMode0GlobalDiplomacyReset(this->nationSlot);

  TSimMgr* localizationTable = g_pSimMgr;
  if (localizationTable != 0 && localizationTable->redrawEnabled != 0) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x6e616d65, this->nationSlot, 0xfffffffd);
  }
}

// FUNCTION: IMPERIALISM 0x004deca0
void TGreatPower::DecrementNeedLevelByNationStep(short nationSlot) {
  short* needLevel = &this->needLevelByNation[nationSlot];
  switch (*needLevel) {
  case 0x4b:
    if (this->treasuryValue10 > 10000) {
      *needLevel = 0x32;
    }
    break;
  case 0x5a:
    *needLevel = 0x4b;
    return;
  case 0x5f:
    *needLevel = 0x5a;
    return;
  case 100:
    *needLevel = 0x5f;
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004dedf0
void TGreatPower::NotifyActionSlot94(int arg1, int arg2) {
  struct Event13Payload {
    int marker0;
    int nationMask;
    int marker1;
    int targetMask;
  };
  const int kMajorNationCount = 7;
  const short kPolicyMutualDefense = 0x130;
  const short kPolicyTradeEmbargo = 0x12E;

  short policyCode = static_cast<short>(arg2);

  if (this->diplomacyEligibilityA0 != 0) {
    int packedCode = (static_cast<int>(static_cast<unsigned short>(arg1)) << 16) |
                     static_cast<unsigned short>(arg2);
    this->turnEventQueue->InsertCopiedRecordSortedByComparator(&packedCode);

    Event13Payload payload;
    payload.marker0 = 1;
    payload.nationMask = 1 << (static_cast<unsigned char>(this->nationSlot) & 0x1F);
    payload.marker1 = 1;
    payload.targetMask = 1 << (static_cast<unsigned char>(arg1) & 0x1F);

    char immediateDispatch = this->ShouldDispatchImmediatelySlot28();
    if (immediateDispatch == 0) {
      if (g_pInterNationEventQueueManager != 0) {
        // The bucket API packs the payload pointer into its int parameter.
        g_pInterNationEventQueueManager->QueueInterNationEventIntoNationBucket(
            static_cast<int>(this->nationSlot), reinterpret_cast<int>(&payload), '\0');
      }
    } else {
      g_pGameFlowState->CreateAndSendTurnEvent13_NationAndNineDwords(
          static_cast<int>(this->nationSlot), &payload.marker0);
    }
  }

  TDiplomacyMgr* diplomacyState = g_pDiplomacyTurnStateManager;
  int nationSlot = static_cast<int>(this->nationSlot);

  if (policyCode == kPolicyMutualDefense &&
      g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(arg1) != 0) {
    for (int slot = 0; slot < kMajorNationCount; ++slot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(slot) == 0) {
        continue;
      }

      short relationState = g_pDiplomacyTurnStateManager->GetRelationTierSlot70(nationSlot, slot);
      if (relationState != 2) {
        continue;
      }

      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(slot, arg1) != 0) {
        g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(nationSlot, slot, 1);
      }
    }
  }

  if (policyCode != kPolicyTradeEmbargo) {
    return;
  }

  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(slot) == 0) {
      continue;
    }

    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(slot, arg1) == 0) {
      continue;
    }

    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(slot, nationSlot) == 0) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(slot, 2, static_cast<short>(arg1));
    }
  }
}

// FUNCTION: IMPERIALISM 0x004defd0
void TGreatPower::QueueDiplomacyProposalCodeForTargetNation(short proposalCode,
                                                            short targetNationId) {
  struct DiplomacyProposalRecord {
    short proposalCode;
    short targetNationId;
  };

  DiplomacyProposalRecord proposalRecord;
  proposalRecord.proposalCode = proposalCode;
  proposalRecord.targetNationId = targetNationId;

  this->proposalQueue->InsertCopiedRecordSortedByComparator(&proposalRecord);
}

// FUNCTION: IMPERIALISM 0x004df010
void TGreatPower::ApplyAcceptedDiplomacyProposalCode(short proposalIndex) {
  struct DiplomacyProposalRecord {
    short proposalCode;
    short targetNationSlot;
  };

  // Three independent destructible shared-string locals, constructed in order
  // and released in reverse. Modeling them as one aggregate scope object adds an
  // EH-state nesting level and reshapes the function; the original has three
  // separate locals (construct 0/1/2, advance ehstate after each).
  CString tmp0;
  CString tmp1;
  CString tmp2;

  DiplomacyProposalRecord* proposal = static_cast<DiplomacyProposalRecord*>(
      this->proposalQueue->GetPtrListEntryByOneBasedIndex(proposalIndex));

  switch (static_cast<int>(proposal->proposalCode) - 0x12D) {
  case 0:
    this->ApplyJoinEmpireModeForTargetNation(static_cast<int>(proposal->targetNationSlot), 1);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          3, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    break;

  case 1: {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 2);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          4, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
              nationSlot, static_cast<int>(proposal->targetNationSlot)) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, nationSlot) ==
              0) {
        this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(
            nationSlot, 2, static_cast<int>(proposal->targetNationSlot));
      }
    }
    break;
  }

  case 2:
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 3);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          5, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    break;

  case 3: {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 4);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          2, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(
            static_cast<int>(proposal->targetNationSlot)) != 0) {
      for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
            g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, nationSlot) ==
                2 &&
            g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                nationSlot, static_cast<int>(proposal->targetNationSlot)) != 0) {
          g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, nationSlot, 1);
        }
      }
    }
    break;
  }

  case 5: {
    g_apTerrainTypeDescriptorTable[static_cast<int>(proposal->targetNationSlot)]
        ->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          3, static_cast<int>(proposal->targetNationSlot), this->nationSlot, '\0');
    }
    break;
  }

  default:
    break;
  }

  if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(
          static_cast<int>(proposal->targetNationSlot)) != 0 &&
      g_pSimMgr->IsNationSlotEligibleForEventProcessing(
          static_cast<int>(proposal->targetNationSlot)) != 0) {
    g_apNationStates[static_cast<int>(proposal->targetNationSlot)]->NotifyActionSlot94(
        this->nationSlot, proposal->proposalCode);
  }
}

// FUNCTION: IMPERIALISM 0x004df370
void TGreatPower::QueueInterNationEventForProposalCode12D_130(unsigned short proposalQueueIndex) {
  const short kProposalCode12D = 0x12D;
  const short kProposalCode12E = 0x12E;
  const short kProposalCode12F = 0x12F;
  const short kProposalCode130 = 0x130;
  const int kEvent09 = 9;
  const int kEvent0B = 11;
  const int kEvent0D = 13;
  const int kEvent07 = 7;

  TSortedByRelationshipList* queue = this->proposalQueue;
  if (queue == 0) {
    return;
  }

  int queueOrdinal = static_cast<int>(static_cast<short>(proposalQueueIndex));
  if (queueOrdinal > queue->GetSize()) {
    return;
  }

  short* proposalEntry = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(queueOrdinal));
  short proposalCode = proposalEntry[0];
  short targetNation = proposalEntry[1];

  TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
  if (diplomacyManager != 0 &&
      g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(targetNation) != 0) {
    TGreatPower* nationState = g_apNationStates[targetNation];
    if (nationState != 0) {
      nationState->NotifyActionSlot94(this->nationSlot, -proposalCode);
    }
  }

  switch (proposalCode) {
  case kProposalCode12D:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent09, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  case kProposalCode12E:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent0B, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  case kProposalCode12F:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent0D, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  case kProposalCode130:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent07, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004df4b0
char TGreatPower::IsEventCodeAllowedForRelationTier(short eventCode, int targetNation) {
  char allowed = 0;
  short relationTier =
      g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, targetNation);
  switch (relationTier) {
  case 2:
    if (eventCode != 0x130 && eventCode != 0x12f && eventCode != 0x12e) {
      return 1;
    }
    break;
  case 3:
    if (eventCode != 0x130 && eventCode != 0x12f) {
      return 1;
    }
    break;
  case 4:
    if (eventCode != 0x130) {
      return 1;
    }
    break;
  case 6:
    if (eventCode == 0x130) {
      allowed = 1;
    }
    break;
  }
  return allowed;
}

// FUNCTION: IMPERIALISM 0x004df580
void TGreatPower::ResetNationDiplomacyProposalQueue(void) {
  TSortedByRelationshipList* proposalQueue = this->proposalQueue;
  if (proposalQueue != 0) {
    proposalQueue->ClearAndFreeAllPtrListRecords();
  }
}

// FUNCTION: IMPERIALISM 0x004df5c0
void TGreatPower::DispatchTurnEvent2103WithNationFromRecord(void) {
  TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;
  if (uiRuntimeContext == 0) {
    return;
  }

  uiRuntimeContext->DispatchTurnEventSlot4C(0x2103, this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004df5f0
void TGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  const short kProposalTradeEmbargo = 0x12E;
  const short kProposalMutualDefense = 0x132;
  CString proposalSummaryRef;
  CString proposalScratchRef;
  int proposalIndex = 0;
  int queueIndex = 0;

  TSortedByRelationshipList* queue = this->proposalQueue;
  short proposalCount = static_cast<short>(queue->GetSize());
  if (proposalCount != 0 && proposalCount > 0) {
    proposalIndex = 1;
    queueIndex = 1;
    TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
    TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;

    do {
      short* proposalEntry = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(queueIndex));
      short proposalCode = proposalEntry[0];
      short targetNation = proposalEntry[1];
      char shouldApplyProposal;

      if (IsTurnCooldownCounterActiveOrResetFlag() == 0) {
        if (this->diplomacyPolicyByNation[targetNation] == proposalCode) {
          shouldApplyProposal = 1;
        } else if (proposalCode == kProposalTradeEmbargo) {
          if (g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, targetNation) !=
              4) {
            shouldApplyProposal = 0;
          } else {
            shouldApplyProposal = uiRuntimeContext->RequestDiplomacyDecisionSlot90(
                this->nationSlot, targetNation, kProposalTradeEmbargo);
          }
        } else {
          shouldApplyProposal = uiRuntimeContext->RequestDiplomacyDecisionSlot90(
              this->nationSlot, targetNation, proposalCode);
        }

        if (shouldApplyProposal == 0) {
          this->QueueInterNationEventForProposalCode12D_130(proposalIndex);
        } else if (proposalCode == kProposalMutualDefense) {
          int checkNation = 0;
          do {
            if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(targetNation,
                                                                        checkNation) != 0 &&
                g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                        checkNation) == 0) {
              this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(checkNation, 0x132,
                                                                         targetNation);
            }
            ++checkNation;
          } while (checkNation < kMajorNationCount);
        } else {
          this->ApplyAcceptedDiplomacyProposalCode(proposalIndex);
        }
      } else {
        this->QueueInterNationEventForProposalCode12D_130(proposalIndex);
      }

      ++proposalIndex;
      ++queueIndex;
    } while (static_cast<short>(proposalIndex) <= proposalCount);
  }

  this->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

// FUNCTION: IMPERIALISM 0x004df810
void TGreatPower::ApplyScenarioRelationPresetAndSpawnFrogCity(TCity* mgr) {
  TPopulationMgr* notifySink = mgr->productionSummary1d8;
  int presetLevel;
  if (this->diplomacyEligibilityA0 == 0) {
    presetLevel = 2;
  } else {
    presetLevel = g_pSimMgr->redrawEnabled;
  }
  const short* presetRow = g_Rebuild_Primary_Nation_Value_00653570[presetLevel];
  for (int needIndex = 0; needIndex < 0x17; ++needIndex) {
    (&mgr->cityStockCottonB6)[static_cast<short>(needIndex)] = presetRow[needIndex];
    mgr->VerifyStocks();
  }
  mgr->productionAccum1fc[8] += 999 - mgr->productionOrderTable1dc[8];
  mgr->productionOrderTable1dc[8] = 999;
  mgr->productionAccum1fc[10] += 999 - mgr->productionOrderTable1dc[10];
  mgr->productionOrderTable1dc[10] = 999;
  mgr->productionAccum1fc[9] += 999 - mgr->productionOrderTable1dc[9];
  mgr->productionOrderTable1dc[9] = 999;
  mgr->productionAccum1fc[7] += 999 - mgr->productionOrderTable1dc[7];
  mgr->productionOrderTable1dc[7] = 999;
  mgr->productionAccum1fc[14] += 999 - mgr->productionOrderTable1dc[14];
  mgr->productionOrderTable1dc[14] = 999;
  mgr->productionAccum1fc[13] += 999 - mgr->productionOrderTable1dc[13];
  mgr->productionOrderTable1dc[13] = 999;
  if (presetLevel == 0) {
    notifySink->NotifyProductionPresetSlot2C(2, 3, 2);
  } else {
    notifySink->NotifyProductionPresetSlot2C(4, 2, 1);
  }
  TSimMgr* localization = g_pSimMgr;
  if (this->diplomacyEligibilityA0 == 0 || localization->redrawEnabled < 2 ||
      localization->stateFlag114 != 0) {
    if (this->ShouldDispatchImmediatelySlot28() == 0 || localization->stateFlag114 != 0) {
      this->CreateFrogCityAtHomeRegionAndAttach(mgr);
      return;
    }
  }
  this->CreateFrogCityTownMarkerAndAttach(mgr);
}

// FUNCTION: IMPERIALISM 0x004dfa20
void TGreatPower::CreateFrogCityTownMarkerAndAttach(void* receiver) {
  TTown* marker = new TTown();
  marker->InitializeTownMarker("Frog City", 0, 1, this->nationSlot);
  static_cast<TCity*>(receiver)->SetSelectedTownMarker(marker);
  marker->activeFlag4f = 1;
  this->townMarkerList->AddTail(marker);
}

// FUNCTION: IMPERIALISM 0x004dfae0
void TGreatPower::CreateFrogCityAtHomeRegionAndAttach(void* receiver) {
  TSimMgr* localization = g_pSimMgr;
  int homeRegionIndex = -1;
  if (localization->stateFlag114 == 0) {
    homeRegionIndex = this->interiorMinister->GetHomeCityRecordIndexSlotC0();
  } else {
    TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
    for (int regionId = 0; regionId < 0x1950; ++regionId) {
      if (static_cast<short>(terrainTable[static_cast<short>(regionId)].ownerNationTag04) ==
              this->nationSlot &&
          (terrainTable[static_cast<short>(regionId)].activeFlags1c & 1) != 0) {
        homeRegionIndex = regionId;
      }
    }
    if (static_cast<short>(homeRegionIndex) == -1) {
      CString message;
      {
        CString prefix("GP#");
        message = prefix;
      }
      message += static_cast<char>('0' + static_cast<char>(this->nationSlot));
      message += " is missing capitol site";
      g_pUiRuntimeContext->RunControlStringProviderAndDispatchLocalizedMessage(
          message, &g_cstrGreatPowerPressureMessage);
    }
  }
  this->homeRegionIndex = static_cast<short>(homeRegionIndex);
  TTown* marker = new TTown();
  marker->InitializeTownMarker("FrogCity", homeRegionIndex, 1, this->nationSlot);
  static_cast<TCity*>(receiver)->SetSelectedTownMarker(marker);
  marker->activeFlag4f = 1;
  this->townMarkerList->AddTail(marker);
  g_pGlobalMapState->LinkRegionToNationSlot134(marker->regionId14, this->nationSlot);
  if (this->diplomacyEligibilityA0 == 0 && this->interiorMinister != 0) {
    this->interiorMinister->NoOpForeignMinisterUtilityStub(receiver);
  }
}

// FUNCTION: IMPERIALISM 0x004dfd30
void TGreatPower::SetHomeCityTileAndDisplayName(short homeRegionTile, char* cityName) {
  TCity* city = this ? this->city : 0;
  void* selectedOrder = city->selectedOrderB0;

  if (homeRegionTile != -1) {
    *(short*)((char*)selectedOrder + 0x14) = homeRegionTile;
  }

  short regionIndex;
  if (city->selectedOrderB0) {
    regionIndex = *(short*)((char*)city->selectedOrderB0 + 0x14);
  } else {
    regionIndex = 1;
  }
  this->homeRegionIndex = regionIndex;

  if (cityName) {
    CString nameStr(cityName);
    short cityRecordIndex = g_pGlobalMapState->terrainStateTable[regionIndex].cityRecordIndex;
    g_pGlobalMapState->SetGlobalMapCellSharedLabel(cityRecordIndex, &nameStr);
    static_cast<TProductionOrder*>(selectedOrder)->ResetCityOrderItemDerivedStateNoop();
  }

  this->RebuildNationResourceYieldCountersAndDevelopmentTargets();

  if (this->interiorMinister) {
    this->interiorMinister->MinisterSlot14();
  }

  if (g_pSimMgr->stateFlag114 == 0) {
    short result1 =
        g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(this->homeRegionIndex, 0);
    TCivUnit* civ1 = new TCivUnit();
    civ1->InitializeCivWorkOrderState(1, result1, this->nationSlot);

    short result2 =
        g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(this->homeRegionIndex, 1);
    TCivUnit* civ2 = new TCivUnit();
    civ2->InitializeCivWorkOrderState(4, result2, this->nationSlot);

    city->orderCountByType5c[1] += 2;

    if (g_pSimMgr->redrawEnabled == 0 && this->diplomacyEligibilityA0) {
      city->orderCountByType5c[1] += 6;

      short result3 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->homeRegionIndex, 0);
      TCivUnit* civ3 = new TCivUnit();
      civ3->InitializeCivWorkOrderState(1, result3, this->nationSlot);

      short result4 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->homeRegionIndex, 0);
      TCivUnit* civ4 = new TCivUnit();
      civ4->InitializeCivWorkOrderState(0, result4, this->nationSlot);

      short result5 = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
          this->homeRegionIndex, 0);
      TCivUnit* civ5 = new TCivUnit();
      civ5->InitializeCivWorkOrderState(2, result5, this->nationSlot);
    }
  }

  g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, this->nationSlot, 0x100);

  this->SeedInitialMilitaryAndNavyOrdersForOwnedRegions();
}

// FUNCTION: IMPERIALISM 0x004e00d0
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) {
  int quarterTick = static_cast<int>(g_pSimMgr->quarterGateTick2c);
  if (static_cast<short>(quarterTick / 4) == 0) {
    return;
  }
  g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
      *message, &g_cstrGreatPowerPressureMessage, 2, 0);
}

// FUNCTION: IMPERIALISM 0x004e0140
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) {
  int quarterTick = static_cast<int>(g_pSimMgr->quarterGateTick2c);
  if (static_cast<short>(quarterTick / 4) == 0) {
    return;
  }
  g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
      *message, &g_cstrGreatPowerPressureMessage, 1, 0);
}

// FUNCTION: IMPERIALISM 0x004e01b0
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) {
  int quarterTick = static_cast<int>(g_pSimMgr->quarterGateTick2c);
  if (static_cast<short>(quarterTick / 4) == 0) {
    return;
  }
  g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
      *message, &g_cstrGreatPowerPressureMessage, 0, 0);
}

// --- Slots 0x4c/0x65/0x6c/0x6f/0x78/0x7d/0x7f/0xac and trivial tail slots ---

// FUNCTION: IMPERIALISM 0x004e0220
void TGreatPower::DispatchTrackedOrderSlot2CCallbacks(void) {
  CIterator orderIter(this->trackedObjectList);
  for (TUnit* order = static_cast<TUnit*>(orderIter.Reset()); orderIter.More();
       order = static_cast<TUnit*>(orderIter.Advance())) {
    order->DispatchSlot2C();
  }
}

// FUNCTION: IMPERIALISM 0x004e0290
void TGreatPower::SortTrackedOrdersByTypePriority(void) {
  short orderCount = static_cast<short>(this->trackedObjectList->GetCount());
  int total = orderCount;
  for (int outer = 1; outer < total; ++outer) {
    void* entryOuter = this->trackedObjectList->GetEntryByOrdinal(outer);
    short outerPriority = g_DAT_006966d0_Value_006966D0[static_cast<TUnit*>(entryOuter)->orderType];
    for (int inner = outer + 1; inner <= total; ++inner) {
      void* entryInner = this->trackedObjectList->GetEntryByOrdinal(inner);
      short innerPriority =
          g_DAT_006966d0_Value_006966D0[static_cast<TUnit*>(entryInner)->orderType];
      if (innerPriority < outerPriority) {
        this->trackedObjectList->SetAtOrdinal(outer, &entryInner, 1);
        this->trackedObjectList->SetAtOrdinal(inner, &entryOuter, 1);
        entryOuter = entryInner;
        outerPriority = innerPriority;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e03a0
void TGreatPower::RunSlot4CThenSortTrackedOrders(void) {
  this->DispatchTrackedOrderSlot2CCallbacks();
  this->SortTrackedOrdersByTypePriority();
}

// FUNCTION: IMPERIALISM 0x004e03d0
void TGreatPower::ResetField900FromNeedCapA6(void) {
  this->field900 = this->needCapA6 / 5;
}

// FUNCTION: IMPERIALISM 0x004e0400
char TGreatPower::HasActiveCandidateNationSlots() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e0420
void TGreatPower::SetCandidateNationFlagAndPortZoneState(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x004e0440
void TGreatPower::NotifyAllianceSlot214(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x004e0460
int TGreatPower::SumNavyOrderPriorityForNationAndNodeType(TZone* zone) {
  int sum = 0;
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 == this->nationSlot && node->field08 == zone) {
      sum += node->ComputeOrderNodeCompositeEconomicScore();
    }
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e04b0
int TGreatPower::SumNavyOrderPriorityForNation() {
  int sum = 0;
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 == this->nationSlot) {
      sum += node->ComputeOrderNodeCompositeEconomicScore();
    }
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e0500
int TGreatPower::SumNavyOrderPriorityForNationSlot86(void) {
  int prioritySum = 0;
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 == this->nationSlot) {
      prioritySum += GetIndustryActionCostWeightByResourceType(node->resourceType04);
    }
  }
  return prioritySum;
}

// FUNCTION: IMPERIALISM 0x004e0550
int TGreatPower::CountMapActionContextNodesWithNationBit(void) {
  int count = 0;
  TZone* node = g_pMapActionContextListHead;
  if (node != 0) {
    do {
      if ((node->nationKeyMask10 & (1 << (this->nationSlot & 0x1f))) != 0) {
        ++count;
      }
      node = node->prev18;
    } while (node != 0);
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x004e0590
double TGreatPower::ComputeMinisterSkillFloatSlot88(void) {
  return g_DAT_Value_00653308[this->foreignMinister->skillIndexC] +
         g_DAT_Value_00653328[this->defenseMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e05d0
double TGreatPower::ComputeMinisterSkillFloatSlot89(void) {
  return g_DAT_Value_00653360[this->defenseMinister->skillIndexC] +
         g_DAT_Value_00653340[this->foreignMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e0610
double TGreatPower::ComputeMinisterSkillFloatSlot8A(void) {
  return g_DAT_Value_00653398[this->defenseMinister->skillIndexC] +
         g_DAT_Value_00653378[this->foreignMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e0650
double TGreatPower::ComputeMinisterSkillFloatSlot8B(void) {
  return g_DAT_006533b0_Value_006533B0[this->foreignMinister->skillIndexC] +
         g_DAT_006533d0_Value_006533D0[this->defenseMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e0690
double TGreatPower::ComputeMinisterSkillFloatSlot8C(void) {
  return g_DAT_006533e8_Value_006533E8[this->foreignMinister->skillIndexC] +
         g_DAT_Value_00653408[this->defenseMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e06d0
int TGreatPower::SumCommodityRecordAccumulatedValues(void) {
  TCity* cityState = this->city;
  int total = 0;
  if (cityState != 0) {
    total = cityState->tradeCommodityRecordPtrs[12]->accumulatedValue +
            cityState->tradeCommodityRecordPtrs[11]->accumulatedValue +
            cityState->tradeCommodityRecordPtrs[9]->accumulatedValue +
            cityState->tradeCommodityRecordPtrs[10]->accumulatedValue +
            cityState->tradeCommodityRecordPtrs[8]->accumulatedValue;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004e0740
int TGreatPower::GetCityBuildingProductionSlot8D(short buildingSlot) {
  if (this->city != 0) {
    return static_cast<short>(this->city->GetBuildingType(buildingSlot));
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e0770
short TGreatPower::ComputeNationRuntimeAdvisoryMetricCase6() {
  TCity* nationCity = this->city;
  if (nationCity != 0) {
    TPopulationMgr* summary = nationCity->productionSummary1d8;
    TPopulationMetricBucket* bucket = summary->productionSlots14;
    // 100% at a file-tail position; the register-allocator picks an esi-spill form here
    // (position-dependent wobble, heuristics 18/47) - keep the natural expression.
    short folded = static_cast<short>(bucket->valueAt8 * 2 + bucket->valueAt6);
    folded = static_cast<short>(folded * 2 + bucket->valueAt4);
    return static_cast<short>(folded + summary->extraAt1e);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e07b0
int TGreatPower::ComputeArmyCommitBudgetSlot8E(void) {
  if (this->city == 0) {
    return 0;
  }
  TPopulationMgr* scenario = this->city->productionSummary1d8;
  short scenarioCap = scenario->stockLevel1c;
  short productionCap = scenario->productionSlots14->valueAt4;
  if (scenarioCap < productionCap) {
    productionCap = scenarioCap;
  }
  int budget = productionCap;
  short metricCap = this->GetDiplomacyExternalStateByTarget(0x10);
  if (static_cast<int>(metricCap) <= budget) {
    budget = metricCap;
  }
  int armyPower = SumMilitaryUnitPowerWeights(this->militaryUnitList44);
  if (armyPower / 2 <= budget) {
    budget = armyPower / 2;
  }
  return budget;
}

// FUNCTION: IMPERIALISM 0x004e0890
float TGreatPower::GetScoreFactorSlot23C(void) {
  int armyPower = SumMilitaryUnitPowerWeights(this->militaryUnitList44);
  float armyPowerF = static_cast<float>(armyPower);
  float commitBudgetF = static_cast<float>(this->ComputeArmyCommitBudgetSlot8E());
  int production = this->GetCityBuildingProductionSlot8D(3);
  int poweredCap = static_cast<int>(armyPowerF * g_Iterate_Linked_List_Value_00653718);
  int productionTerm = static_cast<int>(static_cast<float>(production));
  if (productionTerm >= poweredCap) {
    productionTerm = poweredCap;
  }
  return armyPowerF + commitBudgetF + static_cast<float>(productionTerm);
}

// FUNCTION: IMPERIALISM 0x004e09a0
float TGreatPower::GetScoreFactorSlot240(void) {
  TTechMgr* capabilityState = g_pCityOrderCapabilityState;
  int shipProduction;
  if (capabilityState->resourceTypeEnabled19d[0xb] != 0) {
    shipProduction = this->GetCityBuildingProductionSlot8D(2);
  } else if (capabilityState->resourceTypeEnabled19d[8] != 0) {
    shipProduction =
        (this->GetCityBuildingProductionSlot8D(4) + this->GetCityBuildingProductionSlot8D(2)) / 2;
  } else {
    shipProduction = this->GetCityBuildingProductionSlot8D(4);
  }
  float shipProductionF = static_cast<float>(shipProduction);
  float navyPriorityF = static_cast<float>(this->SumNavyOrderPriorityForNationSlot86());
  int navyPriorityInt = static_cast<int>(navyPriorityF);
  int productionTerm = static_cast<int>(shipProductionF);
  if (productionTerm >= navyPriorityInt) {
    productionTerm = navyPriorityInt;
  }
  float productionTermF = static_cast<float>(productionTerm);
  int fleetPower = SumMilitaryUnitPowerWeights(this->militaryUnitList44);
  int priorityCap = static_cast<int>(navyPriorityF * g_Compute_City_Order_Value_0065371C);
  if (priorityCap >= fleetPower) {
    priorityCap = fleetPower;
  }
  return static_cast<float>(priorityCap) + navyPriorityF + productionTermF;
}

// FUNCTION: IMPERIALISM 0x004e0b20
float TGreatPower::ComputeArmyScoreRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot23C();
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0c10
float TGreatPower::ComputeArmyScoreStandingRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot23C();
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  int yearTerm = GetClampedQuarterYearTerm();
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  float numerator =
      (static_cast<float>(yearTerm) + selfScore) - g_Compute_Advisory_Handler_LookupTable_00653720;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return numerator;
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0d80
float TGreatPower::ComputeNavyScoreRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot240();
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0e70
float TGreatPower::ComputeNavyScoreStandingRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot240();
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  int yearTerm = GetClampedQuarterYearTerm();
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  float numerator =
      (static_cast<float>(yearTerm) + selfScore) - g_Compute_Advisory_Handler_LookupTable_00653720;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return numerator;
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0fe0
float TGreatPower::ComputeArmyScoreRatioVsNationWithSecondary(int targetNation, int secondarySlot) {
  float selfScore = this->GetScoreFactorSlot23C();
  int secondaryPower =
      SumMilitaryUnitPowerWeights(g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList44);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return combinedScore;
  }
  return combinedScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e1170
float TGreatPower::ComputeArmyScoreStandingRatioVsNationPair(int targetNation, int partnerNation) {
  float selfScore = this->GetScoreFactorSlot23C();
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, partnerNation);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore;
  }
  return (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore) /
         denominator;
}

// FUNCTION: IMPERIALISM 0x004e1300
float TGreatPower::ComputeNavyScoreRatioVsNationWithSecondary(int targetNation, int secondarySlot) {
  float selfScore = this->GetScoreFactorSlot240();
  int secondaryPower =
      SumMilitaryUnitPowerWeights(g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList44);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return combinedScore;
  }
  return combinedScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e1490
float TGreatPower::ComputeNavyScoreStandingRatioVsNationPair(int targetNation, int partnerNation) {
  float selfScore = this->GetScoreFactorSlot240();
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, partnerNation);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore;
  }
  return (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore) /
         denominator;
}

// FUNCTION: IMPERIALISM 0x004e1620
float TGreatPower::ComputeArmyScoreRatioForNationPair(int nationA, int nationB, char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot23C();
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot23C();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(opponentNation);
  float denominator = opponentScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  float numerator;
  if (swapRoles == 0) {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724;
  } else {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1750
float TGreatPower::ComputeArmyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                              char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot23C();
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot23C();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(opponentNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(opponentNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      opponentScore;
  float numerator;
  if (swapRoles == 0) {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724) +
                selfScore;
  } else {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714) +
                selfScore;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1910
float TGreatPower::ComputeNavyScoreRatioForNationPair(int nationA, int nationB, char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot240();
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot240();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(opponentNation);
  float denominator = opponentScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  float numerator;
  if (swapRoles == 0) {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724;
  } else {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1a40
float TGreatPower::ComputeNavyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                              char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot240();
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot240();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(opponentNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(opponentNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      opponentScore;
  float numerator;
  if (swapRoles == 0) {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724) +
                selfScore;
  } else {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714) +
                selfScore;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1c00
char TGreatPower::ReturnZeroSlot9D(int targetNation) {
  (void)targetNation;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e1c20
char TGreatPower::EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation) {
  // Result intentionally ignored in the original; keep the call for its side effects.
  g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, targetNation);
  char joinsWar = 0;
  TGreatPower* targetState = g_apNationStates[targetNation];
  if (targetState->CompareMissionScoreVariantsByMode(0) == 0 &&
      targetState->CompareMissionScoreVariantsByMode(1) == 0) {
    float warThreshold = this->ComputeWarThresholdSlotA3(targetNation);
    if (this->ComputeMinisterSkillFloatSlot8C() < warThreshold) {
      joinsWar = 1;
      for (int otherNation = 0; otherNation < 7; ++otherNation) {
        if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(otherNation) != 0 &&
            g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, otherNation) ==
                2 &&
            g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(otherNation, targetNation) !=
                0) {
          g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, otherNation, 1);
        }
      }
    }
  }
  if (joinsWar != 0) {
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1c, targetNation,
                                                                        this->nationSlot, 0);
  }
  return joinsWar;
}

// FUNCTION: IMPERIALISM 0x004e1d50
int TGreatPower::CheckTransitionSlot27C(int arg1, int arg2) {
  char result = 0;
  TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;

  result = g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, arg2);

  if (result == 0) {
    result = uiRuntimeContext->RequestDecisionSlot94(this->nationSlot, arg1, arg2, 0x0A);
    if (result != 0) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(arg2, 1, arg1);
      return true;
    }
  } else {
    result = uiRuntimeContext->RequestDecisionSlot94(this->nationSlot, arg1, arg2, 0x0B);
    if (result != 0) {
      TMinor* secondaryNationState = g_apSecondaryNationStateSlots[arg1];
      if (secondaryNationState != 0) {
        short stateValue = secondaryNationState->DecodeOwnerNationSlot();
        if (stateValue != this->nationSlot) {
          secondaryNationState->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
        }
      }
    }
  }
  return result != 0;
}

bool TGreatPower::ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2) {
  return this->CheckTransitionSlot27C(arg1, arg2) != 0;
}

// FUNCTION: IMPERIALISM 0x004e1e40
int TGreatPower::PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) {
  this->SetCandidateNationFlagAndPortZoneState(targetNation);
  this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetNation, mode, sourceNation);
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e1f20
void TGreatPower::SelectAndQueueAdvisoryMapMissionsCase16(void) {}

// --- Relative military/naval power score family (vtable slots 0x8e-0x9e) ---
// Helpers live in TGreatPower_power_score.cpp (TGreatPower_internal.h).

// FUNCTION: IMPERIALISM 0x004e1f40
float TGreatPower::ComputeWarThresholdSlotA3(int targetNation) {
  float selfArmyScore = TruncatedScoreFactorToFloat(this->GetScoreFactorSlot23C());
  float selfNavyScore = TruncatedScoreFactorToFloat(this->GetScoreFactorSlot240());
  float alliedArmyForSelf = 0.0f;
  float alliedNavyForSelf = 0.0f;
  float alliedArmyForTarget = 0.0f;
  float alliedNavyForTarget = 0.0f;

  int nationIndex = 0;
  while (nationIndex < kMajorNationCount) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationIndex, this->nationSlot) !=
            0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationIndex) != 0 &&
        nationIndex != targetNation) {
      TGreatPower* allyState = g_apNationStates[nationIndex];
      alliedArmyForSelf += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot23C());
      alliedNavyForSelf += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot240());
    }
    ++nationIndex;
  }

  nationIndex = 0;
  while (nationIndex < kMajorNationCount) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationIndex, targetNation) != 0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationIndex) != 0 &&
        nationIndex != this->nationSlot) {
      TGreatPower* allyState = g_apNationStates[nationIndex];
      alliedArmyForTarget += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot23C());
      alliedNavyForTarget += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot240());
    }
    ++nationIndex;
  }

  char borderLinked = 0;
  if (g_pGlobalMapState != 0) {
    borderLinked =
        g_pGlobalMapState->AreNationsBorderLinked(targetNation, static_cast<int>(this->nationSlot));
  }

  TGreatPower* targetState = g_apNationStates[targetNation];
  if (borderLinked != 0) {
    float targetArmyScore = TruncatedScoreFactorToFloat(targetState->GetScoreFactorSlot23C());
    float numerator =
        selfArmyScore + alliedArmyForSelf * (-g_Compute_Advisory_Peer_LookupTable_00653724);
    float denominator =
        targetArmyScore + alliedArmyForTarget * (-g_Compute_Advisory_Peer_LookupTable_00653724);
    return numerator / denominator;
  }

  float targetNavyScore = TruncatedScoreFactorToFloat(targetState->GetScoreFactorSlot240());
  float numerator =
      selfNavyScore + alliedNavyForSelf * (-g_Compute_Advisory_Peer_LookupTable_00653724);
  float denominator =
      targetNavyScore + alliedNavyForTarget * (-g_Compute_Advisory_Peer_LookupTable_00653724);
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e2190
void TGreatPower::PruneInvalidTrackedEntriesAndNotifyOwner(void) {}

// FUNCTION: IMPERIALISM 0x004e21b0
void TGreatPower::ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode) {
  CString sharedStringScope;

  TCountry::ApplyJoinEmpireModeForTargetNation(targetNationSlot, mode);

  if (targetNationSlot >= 0 && targetNationSlot < kNationSlotCount) {
    TGreatPower* targetNation = g_apNationStates[targetNationSlot];
    if (targetNation != 0 && targetNation->field8d1 < 3) {
      targetNation->SetNationPendingActionStateAndPayload(9, this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2270
void TGreatPower::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  this->ownedRegionList->Delete(regionId);
  this->NotifyRegionEventSlot298(regionId);
}

// FUNCTION: IMPERIALISM 0x004e22b0
void TGreatPower::AddRegionIdToNationOwnedRegionList(int regionId) {
  this->ownedRegionList->InsertLast(regionId);
  if (this->ownedRegionList->GetSize() >= 9) {
    signed char pressureHigh = this->serializedStatusFlags[6];
    pressureHigh = pressureHigh >= 0x33;
    if (pressureHigh != 0) {
      signed char gateHigh = this->expansionEventGate;
      gateHigh = gateHigh >= 0x33;
      if (gateHigh == 0) {
        this->SetNationPendingActionStateAndPayload(0x0C, -1);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2330
void TGreatPower::SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot,
                                                                int policyCode) {
  const int kPolicyDefensivePact = 500;
  const int kPolicyTradeAgreement = 200;

  short targetNation = static_cast<short>(targetNationSlot);
  if (policyCode == kPolicyDefensivePact || policyCode != kPolicyTradeAgreement) {
    this->needLevelByNation[targetNation] = 100;
  } else {
    int resolvedNation = ResolveTerrainNationSlotFromTarget(targetNation);
    this->needLevelByNation[targetNation] =
        this->needLevelByNation[static_cast<short>(resolvedNation)];
  }

  this->diplomacyGrantByNation[targetNation] = -1;

  if (policyCode == kPolicyDefensivePact) {
    TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
    this->diplomacyPolicyByNation[targetNation] = -1;
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNation, 4);
    this->NotifyAllianceSlot214(targetNation);
    return;
  }

  if (policyCode != kPolicyTradeAgreement) {
    this->SetCandidateNationFlagAndPortZoneState(targetNation);
    return;
  }

  if (this->candidateNationFlags[targetNation] == 0) {
    int resolvedNation = ResolveTerrainNationSlotFromTarget(targetNation);
    if (this->candidateNationFlags[static_cast<short>(resolvedNation)] == 0) {
      TDiplomacyMgr* diplomacyManager = g_pDiplomacyTurnStateManager;
      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                  resolvedNation) == 0) {
        this->NotifyAllianceSlot214(targetNation);
        return;
      }
    }
  }

  this->SetCandidateNationFlagAndPortZoneState(targetNation);
}

// FUNCTION: IMPERIALISM 0x004e2500
void TGreatPower::NotifyRegionEventSlot298(int ownerClass) {
  // 0x004e2500 reads the tile index from each payload (+0x06) and dispatches
  // [vt+0x30]/[vt+0x1c] directly on the payload — the entries are TUnit-family
  // order objects, and the original has no per-entry null checks.
  TMapMgr* globalMapState = g_pGlobalMapState;
  TSortedList* trackedList = this->trackedObjectList;
  for (int index = trackedList->GetCount(); index != 0; --index) {
    TUnit* order = static_cast<TUnit*>(trackedList->GetEntryByOrdinal(index));
    short orderCityRecord = globalMapState->terrainStateTable[order->tileIndex06].cityRecordIndex;
    if (orderCityRecord == ownerClass) {
      order->DetachUnitOrderFromOwnerAndReset();
      order->Free();
    }
  }

  TSortedList* unitList = this->militaryUnitList44;
  for (int unitIndex = unitList->GetCount(); unitIndex != 0; --unitIndex) {
    TUnit* unit = static_cast<TUnit*>(unitList->GetEntryByOrdinal(unitIndex));
    if (unit->tileIndex06 == -1) {
      unit->Free();
    }
  }
}

void TGreatPower::ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass) {
  this->NotifyRegionEventSlot298(ownerClass);
}

// FUNCTION: IMPERIALISM 0x004e25c0
void TGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) {
  this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(targetNation), 100);
  this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, -1);
  for (int nation = 0; nation < 0x17; ++nation) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, nation) != 0) {
      this->CallSlotA8(nation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2630
void TGreatPower::CallSlotA8(int targetNationSlot) {
  const int kMajorPolicyNation = 7;
  int tableIndex = 0;
  while (tableIndex < 16) {
    if (g_apMinorNationCapabilityObjects[tableIndex] != 0) {
      TMinor* auxRuntimeState = g_apNationAuxRuntimeStateSlots[tableIndex];
      if (auxRuntimeState != 0 &&
          auxRuntimeState->HasMinorStandingLinkSlot5C(this->nationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(kMajorPolicyNation,
                                                                  targetNationSlot) == 0) {
        g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(kMajorPolicyNation,
                                                                    targetNationSlot, 6, 0);
        if (targetNationSlot < kMajorNationCount &&
            g_pSimMgr->IsNationSlotEligibleForEventProcessing(targetNationSlot) != 0) {
          TGreatPower* targetState = g_apNationStates[targetNationSlot];
          if (targetState != 0 && targetState->diplomacyEligibilityA0 == 0) {
            targetState->NotifyActionSlot94(kMajorPolicyNation, 0x131);
          }
        }
        auxRuntimeState->ClearNationAuxRuntimeGrantSlotC4(-1);
        auxRuntimeState->NotifyNationAuxRuntimeFinalizeSlotC0();
      }
    }
    ++tableIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004e2720
void TGreatPower::CallSlotA9(int targetNationSlot) {
  const int kMajorPolicyNation = 7;
  int tableIndex = 0;
  while (tableIndex < 16) {
    if (g_apMinorNationCapabilityObjects[tableIndex] != 0) {
      TMinor* auxRuntimeState = g_apNationAuxRuntimeStateSlots[tableIndex];
      if (auxRuntimeState != 0 &&
          auxRuntimeState->HasMinorStandingLinkSlot5C(this->nationSlot) != 0) {
        g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(kMajorPolicyNation,
                                                                 targetNationSlot, 4);
        if (this->colonyBoycottFlags[targetNationSlot] == 0) {
          auxRuntimeState->SetDiplomacyStandingSlot48(targetNationSlot, 100);
        }
      }
    }
    ++tableIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004e27b0
void TGreatPower::DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode) {
  if (static_cast<short>(mode) == 6) {
    this->CallSlotA8(targetNationSlot);
    return;
  }

  this->CallSlotA9(targetNationSlot);
}

// FUNCTION: IMPERIALISM 0x004e27f0
void TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                       int policyCode,
                                                                       int sourceNationSlot) {
  g_pDiplomacyTurnStateManager->QueueNationPairWarTransition(this->nationSlot,
                                                             static_cast<short>(targetNationSlot));

  short proposalCode = static_cast<short>(policyCode);
  if ((proposalCode != 1) && (proposalCode != 0x132)) {
    return;
  }

  TMinor* secondaryNationState = g_apSecondaryNationStateSlots[sourceNationSlot];
  if (secondaryNationState == 0) {
    return;
  }

  short selectedSlot = secondaryNationState->DecodeOwnerNationSlot();

  if (selectedSlot == this->nationSlot) {
    return;
  }

  secondaryNationState->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
}

// FUNCTION: IMPERIALISM 0x004e2880
int TGreatPower::ClassifyNationProductionTierVsPeers(void) {
  if (this->city == 0) {
    return 0;
  }
  float sampleCount = 0.0f;
  float productionSum = 0.0f;
  float productionSquares = 0.0f;
  int slot = 0;
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(slot) != 0) {
      TCity* peerMgr = (*nationCursor != 0) ? (*nationCursor)->city : 0;
      if (peerMgr != 0) {
        int production = 4;
        for (int buildingSlot = 0; buildingSlot < 7; ++buildingSlot) {
          peerMgr = (*nationCursor != 0) ? (*nationCursor)->city : 0;
          production +=
              static_cast<short>(peerMgr->GetBuildingType(static_cast<short>(buildingSlot)));
        }
        sampleCount = sampleCount - g_Classify_Nation_Military_Value_00653704;
        productionSum = static_cast<float>(production) + productionSum;
        productionSquares = static_cast<float>(production * production) + productionSquares;
      }
    }
    ++nationCursor;
    ++slot;
  } while (nationCursor < g_apNationStates + kMajorNationCount);
  if (sampleCount < g_Classify_Nation_Military_Value_00653708) {
    return 2;
  }
  float mean = productionSum / sampleCount;
  float deviation = static_cast<float>(
      sqrt(((mean * mean * sampleCount - (mean * productionSum + mean * productionSum)) +
            productionSquares) /
           (sampleCount - g_Classify_Nation_Military_Value_0065370C)));
  int ownProduction = 4;
  for (int buildingSlot = 0; buildingSlot < 7; ++buildingSlot) {
    ownProduction +=
        static_cast<short>(this->city->GetBuildingType(static_cast<short>(buildingSlot)));
  }
  float ownScore = static_cast<float>(ownProduction);
  if (mean - deviation * g_Classify_Nation_Military_Value_00653710 < ownScore) {
    return 4;
  }
  if (deviation + mean < ownScore) {
    return 3;
  }
  if (mean - deviation <= ownScore) {
    return 2;
  }
  if (mean - (deviation + deviation) <= ownScore) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e2b00
void TGreatPower::DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) {
  struct TurnOrderDispatchPacket {
    short turnTick;
    short orderKind;
    short payload;
    short flags;
  };

  short turnTick = 0;
  TSimMgr* localizationRuntime = g_pSimMgr;
  if (localizationRuntime != 0) {
    turnTick = localizationRuntime->GetTurnTickSlot3C();
  }

  TurnOrderDispatchPacket packet;
  packet.turnTick = turnTick;
  packet.orderKind = orderKind;
  packet.payload = payload;
  packet.flags = flags;

  TSortedByRelationshipList* turnSummaryQueue = this->turnSummaryQueue;
  if (turnSummaryQueue != 0) {
    turnSummaryQueue->InsertCopiedRecordSortedByComparator(&packet);
  }
}

// FUNCTION: IMPERIALISM 0x004e2b70
void TGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {
  if (this->turnSummaryQueue == 0) {
    return;
  }

  TSortedByRelationshipList* summaryQueue = this->turnSummaryQueue;
  int queueCount = summaryQueue->GetSize();
  if (queueCount <= 0) {
    return;
  }

  short activeTurn = 0;
  TSimMgr* localizationRuntime = g_pSimMgr;
  if (localizationRuntime != 0) {
    activeTurn = static_cast<short>(localizationRuntime->GetTurnTickSlot3C() - 1);
  }

  int mergedNationMask = 0;
  bool foundCurrentTurnEntry = false;

  for (int queueIndex = 1; queueIndex <= queueCount; ++queueIndex) {
    short* entry = static_cast<short*>(summaryQueue->GetPtrListEntryByOneBasedIndex(queueIndex));
    if (entry == 0 || entry[0] != activeTurn) {
      continue;
    }

    foundCurrentTurnEntry = true;
    mergedNationMask |= 1 << (static_cast<int>(entry[1]) & 0x1F);
  }

  if (!foundCurrentTurnEntry) {
    return;
  }

  TNewsMgr* queueManager = g_pInterNationEventQueueManager;
  if (queueManager != 0) {
    queueManager->QueueInterNationEventIntoNationBucket(0x13A0, mergedNationMask, '\0');
  }
}

// Army-plus-navy power score: land units weighted by the per-type table scaled by
// quality percent, plus the same shape over this nation's navy primary orders with a
// local per-type weight table.
// FUNCTION: IMPERIALISM 0x004e3060
int TGreatPower::ComputeNationNavyOrderWeightedMovementScore() {
  int navyWeightByType[14];
  navyWeightByType[0] = 0;
  navyWeightByType[1] = 0;
  navyWeightByType[2] = 0;
  navyWeightByType[3] = 0x96;
  navyWeightByType[4] = 0x12c;
  navyWeightByType[5] = 0;
  navyWeightByType[6] = 0;
  navyWeightByType[7] = 0xc8;
  navyWeightByType[8] = 0x190;
  navyWeightByType[9] = 0x28a;
  navyWeightByType[10] = 0;
  navyWeightByType[11] = 0x1c2;
  navyWeightByType[12] = 0x5dc;
  navyWeightByType[13] = 0x4b0;
  int score = 0;
  CIterator iter(militaryUnitList44);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->GetUnitMovementClassId() > 0) {
      score += g_anWeightedNeighborUnitScoreByType_006955F0[unit->orderType] *
               (static_cast<short>(unit->field_38 / 100) + 10) / 10;
    }
  }
  for (TShip* node = GetNavyPrimaryOrderListHead(); node != 0; node = node->nextOlder24) {
    if (node->ownerNationSlot14 != nationSlot) {
      continue;
    }
    score += navyWeightByType[node->resourceType04] *
             (static_cast<short>(node->field30 / 100) + 10) / 10;
  }
  return score;
}

// Average bilateral relation-standing score against every other live descriptor slot.
// FUNCTION: IMPERIALISM 0x004e3220
int TGreatPower::RecomputeNationComparativePowerMetrics_Impl() {
  TDiplomacyMgr* diplomacy = g_pDiplomacyTurnStateManager;
  int sum = 0;
  int count = 0;
  for (int i = 0; i < kTerrainTypeDescriptorTableCount; i++) {
    if (g_apTerrainTypeDescriptorTable[i] == 0) {
      continue;
    }
    if (i == nationSlot) {
      continue;
    }
    sum += diplomacy->relationStandingScoreMatrix79c[nationSlot * 0x17 + static_cast<short>(i)];
    count++;
  }
  return sum / count;
}

// Sums the encoded diplomacyGrantByNation entries (masking off the top 2 flag bits),
// skipping the 0xffff "no grant" sentinel. Used by the grants/aid screen's "Total"
// row (TGrantsView::ApplyRectSlot110).
// FUNCTION: IMPERIALISM 0x004e3620
int TGreatPower::SumDiplomacyGrantEntriesMaskedToValueBits() {
  int total = 0;
  for (int i = 0; i < 0x17; ++i) {
    unsigned short entry = static_cast<unsigned short>(diplomacyGrantByNation[i]);
    if (entry != 0xffff) {
      total += entry & 0x3fff;
    }
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004e6c20
void TGreatPower::InitializeNationMinisterSubsystemsByPolicyIds(int arg1, int arg2, short arg3,
                                                                short arg4, short arg5) {
  // TODO: promote body @ 0x004e6c20 (1160 bytes, 3 jump-table switches over policy
  // IDs) -- creates defense/foreign/city-interior minister objects, stores at
  // +0x94/+0x98/+0x9c. Most callees are now real: every personality's
  // ConstructTXMinisterBaseState (Napoleon/Bismarck/Pirate/Defender/Bully/Ted/Bill/
  // Diplomat/Textile/Trader/Arms) and all five TDefenseMinister order-array presets
  // (InitializeOrderArrayPreset*, TDefenseMinister.cpp) are ported. Remaining blockers:
  // the WrapperFor_thunk_InitializeCityInteriorMinister_At* stubs (city-minister-family
  // construction, called from the same switch) still need investigation.
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
}

// FUNCTION: IMPERIALISM 0x004e8750
float TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                                 TZone* zone,
                                                                 int selectedNationSlot) {
  float result;
  switch (metricCase) {
  case 1: {
    float sum = 0.0f;
    int slot;
    for (slot = 0; slot < kMajorNationCount; ++slot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) {
        sum += g_apNationStates[slot]->GetScoreFactorSlot23C();
        if (slot == selectedNationSlot) {
          result = g_apNationStates[slot]->GetScoreFactorSlot23C();
        }
      }
    }
    if (result == g_Compute_Advisory_Zero_00653FD0) {
      result = 1.0f;
    }
    result =
        static_cast<float>(g_pSimMgr->GetField30() * result - g_Compute_Advisory_MinusSix_00653FE8);
    return (sum - g_Compute_Advisory_MinusSix_00653FE8) / result;
  }
  case 2: {
    float sum = 0.0f;
    int slot;
    for (slot = 0; slot < kMajorNationCount; ++slot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) {
        sum += g_apNationStates[slot]->GetScoreFactorSlot240();
        if (slot == selectedNationSlot) {
          result = g_apNationStates[slot]->GetScoreFactorSlot240();
        }
      }
    }
    if (result == g_Compute_Advisory_Zero_00653FD0) {
      result = 1.0f;
    }
    result =
        static_cast<float>(g_pSimMgr->GetField30() * result - g_Compute_Advisory_MinusSix_00653FE8);
    return (sum - g_Compute_Advisory_MinusSix_00653FE8) / result;
  }
  case 3: {
    int ownedRegionCount =
        g_apTerrainTypeDescriptorTable[selectedNationSlot]->ownedRegionList->GetSize();
    result = static_cast<float>(
        g_apTerrainTypeDescriptorTable[selectedNationSlot]->ComputeWeightedNeighborLinkScoreForNode(
            cityIndex) *
        ownedRegionCount);
    return (g_apTerrainTypeDescriptorTable[selectedNationSlot]
                ->SumWeightedNeighborLinkScoreForLinkedNodes() -
            g_Compute_Advisory_MinusHundred_00653FF0) /
           (result - g_Compute_Advisory_Map_Value_00653FD4);
  }
  case 4: {
    if (selectedNationSlot >= 7) {
      return g_Compute_Advisory_Zero_00653FD0;
    }
    TGreatPower* nation = g_apNationStates[selectedNationSlot];
    result = static_cast<float>(nation->SumNavyOrderPriorityForNationAndNodeType(zone) *
                                nation->CountMapActionContextNodesWithNationBit());
    return (g_apNationStates[selectedNationSlot]->SumNavyOrderPriorityForNation() -
            g_Compute_Advisory_MinusSix_00653FE8) /
           (result - g_Compute_Advisory_MinusSixFloat_00653FF8);
  }
  case 5:
    return g_Compute_Advisory_Hundred_00654000 /
           g_pDiplomacyTurnStateManager
               ->relationStandingScoreMatrix79c[nationSlot * kNationSlotCount +
                                                static_cast<short>(selectedNationSlot)];
  case 6: {
    const TGlobalMapCityScoreRecord* record = &g_pGlobalMapState->cityScoreTable[cityIndex];
    result = static_cast<float>(record->cityScoreValue) / g_pGlobalMapState->cityScoreTotal;
    short claimantTag =
        g_pGlobalMapState->cityScoreTable[static_cast<short>(cityIndex)].formerOwnerNationCode01;
    if (claimantTag == nationSlot) {
      short ownerTag = record->ownerNationCode00;
      if (ownerTag != nationSlot &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, ownerTag) != 0) {
        return result * g_Compute_Advisory_OnePointFive_00654008;
      }
    }
    break;
  }
  case 7:
    return static_cast<float>(zone->ComputeMapActionContextNodeValueAverage()) /
           g_pActiveMapOrderContext->ComputeGlobalMapActionContextNodeValueAverage();
  }
  return result;
}
// FUNCTION: IMPERIALISM 0x004e8c20
float TGreatPower::ComputeAdvisoryMapNodeCompositeScore(int cityRecordIndex, int mode) {
  return ComputeAdvisoryMapNodeCompositeScoreByMode(cityRecordIndex, mode, -1);
}

// FUNCTION: IMPERIALISM 0x004e8c50
float TGreatPower::ComputeAdvisoryMapNodeCompositeScoreByMode(int cityRecordIndex, int mode,
                                                              int linkCityRecordIndex) {
  int ownerTag = g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode00;
  if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(ownerTag) != 0) {
    if (mode == 0) {
      float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
      float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
      float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
      float score = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag) *
                    f5 * f3 * f1 * f1;
      return score * score;
    }
    if (mode == 1) {
      int linkOwnerTag = g_pGlobalMapState->cityScoreTable[linkCityRecordIndex].ownerNationCode00;
      if (linkOwnerTag != ownerTag) {
        return g_Compute_Advisory_Zero_00653FD0;
      }
      float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
      float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
      float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
      float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
      float score =
          ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, linkCityRecordIndex, 0, linkOwnerTag) *
          f6 * f5 * f3 * f1;
      return score * score;
    }
    TZone* zone =
        g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(cityRecordIndex);
    float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
    float f2 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, cityRecordIndex, 0, ownerTag);
    float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
    float f4 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, cityRecordIndex, zone, ownerTag);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
    float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
    return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, cityRecordIndex, zone, ownerTag) * f6 *
           f4 * f5 * f2 * f3 * f1;
  }
  if (mode == 0) {
    float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
    return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag) * f5 * f3;
  }
  if (mode == 1) {
    int linkOwnerTag = g_pGlobalMapState->cityScoreTable[linkCityRecordIndex].ownerNationCode00;
    if (linkOwnerTag != ownerTag) {
      return g_Compute_Advisory_Zero_00653FD0;
    }
    float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
    float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
    float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
    return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, linkCityRecordIndex, 0, linkOwnerTag) *
           f6 * f5 * f3 * f1;
  }
  TZone* zone =
      g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(cityRecordIndex);
  float f1 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(1, cityRecordIndex, 0, ownerTag);
  float f3 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(3, cityRecordIndex, 0, ownerTag);
  float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, cityRecordIndex, 0, ownerTag);
  float f6 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(6, cityRecordIndex, 0, ownerTag);
  return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, cityRecordIndex, zone, ownerTag) * f6 *
         f5 * f3 * f1;
}

// FUNCTION: IMPERIALISM 0x004e9060
float TGreatPower::ComputeMapActionContextCompositeScoreForNation(TZone* zone) {
  unsigned char* candidateFlags = this->candidateNationFlags;
  int activeCandidateCount = 0;
  int selectedCandidateIndex = 0;
  float compositeScore = 0.0f;
  int i;

  for (i = 0; i < 0x17; ++i) {
    if (candidateFlags[i] != 0) {
      ++activeCandidateCount;
    }
  }

  if (activeCandidateCount == 0) {
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->InitializeRelationshipRecordSize();
    g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(this->nationSlot, 1,
                                                              relationshipList);
    selectedCandidateIndex =
        *static_cast<short*>(relationshipList->GetPtrListEntryByOneBasedIndex(1));
    if (relationshipList != 0) {
      relationshipList->ReleasePtrList();
    }
  } else if (activeCandidateCount == 1) {
    while (selectedCandidateIndex < 0x17) {
      if (candidateFlags[selectedCandidateIndex] != 0) {
        break;
      }
      ++selectedCandidateIndex;
    }
    if (selectedCandidateIndex >= 0x17) {
      // Original artifact: an exhausted scan falls back to the raw argument bits
      // (dead in practice -- activeCandidateCount == 1 guarantees a hit).
      selectedCandidateIndex = reinterpret_cast<int>(zone);
    }
  } else {
    short navyPriorities[7] = {0, 0, 0, 0, 0, 0, 0};
    for (i = 0; i < kMajorNationCount; ++i) {
      if (candidateFlags[i] != 0) {
        navyPriorities[i] =
            static_cast<short>(g_apNationStates[i]->SumNavyOrderPriorityForNationAndNodeType(zone));
      }
    }

    int maxPriority = 0;
    for (i = 0; i < 7; ++i) {
      if (navyPriorities[i] > maxPriority) {
        maxPriority = navyPriorities[i];
        selectedCandidateIndex = i;
      }
    }
    if (maxPriority == 0) {
      compositeScore = 1.0f;
    }
  }

  if (compositeScore == g_Compute_Advisory_Zero_00653FD0) {
    float f2 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, -1, zone, selectedCandidateIndex);
    float f4 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, -1, zone, selectedCandidateIndex);
    float f5 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, -1, zone, selectedCandidateIndex);
    float f7 = ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, -1, zone, selectedCandidateIndex);
    compositeScore = f5 * f7 * f2 * f4;
  }

  return compositeScore;
}

// FUNCTION: IMPERIALISM 0x00582630
void TGreatPower::HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw) {
  STurnInstructionCiviCursor* instruction =
      static_cast<STurnInstructionCiviCursor*>(pInstructionRaw);
  if (instruction == 0 || instruction->tokenCursor == 0) {
    return;
  }

  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token0 = *cursor++;
  unsigned int token1 = *cursor++;
  instruction->tokenCursor = cursor;

  short workOrderType = static_cast<short>((token0 >> 0x10) & 0xFFFF);
  short ownerNationSlot = static_cast<short>((token1 >> 0x10) & 0xFFFF);

  signed char cityOwnerTag = 0;
  if (g_pGlobalMapState != 0) {
    TTerrainStateRecordView* tileTable = g_pGlobalMapState->terrainStateTable;
    if (tileTable != 0) {
      cityOwnerTag = tileTable[ownerNationSlot].ownerNationTag04;
    }
  }

  TCivUnit* orderObject = new TCivUnit();
  if (orderObject == nullptr) {
    return;
  }
  orderObject->InitializeCivWorkOrderState(workOrderType, ownerNationSlot,
                                           static_cast<int>(cityOwnerTag));
}

void TGreatPower::AbsorbCityNeedVectorSlotFC(short*) {}

// Ghidra mislabels this 0x005b7f50 leaf "ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl";
// the body is a pure range predicate (no resource delta, no nation totals), renamed by
// behavior per Hard Rule 6. Genuinely __stdcall (RET 0x4, single stacked short, no ecx);
// FPO leaf (no ebp frame) so it is wrapped in the frame-pointer-omission pragma.

// FUNCTION: IMPERIALISM 0x005b7f50
char __stdcall IsSpecialNationInteractionResource(short resourceIndex) {
  if (resourceIndex >= 0xD && resourceIndex <= 0x10) {
    return 1;
  }
  return 0;
}
