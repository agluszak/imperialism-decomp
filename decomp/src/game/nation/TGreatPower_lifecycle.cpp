// TGreatPower construction, serialization and pending-action dispatch (Mac UCountry.cpp).

#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include <math.h>
#include <stddef.h>
#include <string.h>

#include "decomp_types.h"
#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/GameAssert.h"
#include "game/globals/global_types.h"
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
#include "game/nation/TForeignMinister.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/map/TMinister.h"
#include "game/military/TMilitaryUnit.h"
#include "game/city_ui/TProvinceDesirabilityList.h"
#include "game/nation/TMinor.h"
#include "game/nation/TTurnStartEvent.h"
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
#include "game/TList.h"
#include "game/ui_core/TPtrList.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/city/TTown.h"
#include "game/military/TUnit.h"
#include "game/ui_screens/turn_flow_cooldown.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/TZone.h"
#include "game/gfx/ui_invalidation_guard.h"

static const int kDiplomacyTrackedSlotCount = 0x11;

// FUNCTION: IMPERIALISM 0x004d84b0
int TGreatPower::GetMilitaryRank() {
  float count = 0.0f;
  float sumPower = 0.0f;
  float sumPowerSq = 0.0f;

  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (!g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot))) {
      continue;
    }

    TGreatPower* nation = g_apNationStates[nationSlot];
    int weightSum = 0;
    CIterator unitIter(nation->militaryUnitList);
    for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
      weightSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
    }

    int power = weightSum + nation->GetArmsInNavy() + 4;
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
  CIterator myUnitIter(militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(myUnitIter.Reset()); myUnitIter.More();
       unit = static_cast<TMilitaryUnit*>(myUnitIter.Advance())) {
    myWeightSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  float myPower = static_cast<float>(myWeightSum + GetArmsInNavy() + 4);

  if (myPower > mean + 2.0f * stddev) {
    return 4;
  }
  if (myPower > mean + stddev) {
    return 3;
  }
  if (myPower >= mean - stddev) {
    return 2;
  }
  if (myPower >= mean - 2.0f * stddev) {
    return 1;
  }
  return 0;
}

IMPLEMENT_DYNCREATE(TGreatPower, TCountry)

// FUNCTION: IMPERIALISM 0x004d89f0
TGreatPower::TGreatPower()
    : foreignMinister(0), interiorMinister(0), defenseMinister(0), diplomacyEligibility(0),
      availableMerchantCapacity(0), merchantCapacity(0), transportCapacity(0),
      reservedTransportCapacity(0), grantTotalCost(0), unfilledTradeOfferCount(0),
      budgetPoolBase(0), budgetPoolDelta(0), turnEventQueue(0), proposalQueue(0), city(0),
      townMarkerList(0), trackedObjectList(0), scenarioInitFlag(0), diplomacyBudgetBase(0),
      escalationCounter(0), pendingCommitmentCost(0), pressureCounter(0), armyTransportRemaining(0),
      turnSummaryQueue(0), turnStartEvents(0), specialResourceTradeBalance(0),
      aidAllocationTotal(0), militaryExpenses(0) {
  // TCountry base scalars (identity strings constructed by the TCountry ctor).
  this->nationSlot = 0;
  this->encodedNationSlot = 0;
  this->treasuryValue = 0;
  this->field42 = 0;
  this->militaryUnitList = 0;
  this->homeTileIndex = 0;
  this->ownedRegionList = 0;

  int localeIndex = 0;
  if (g_pSimMgr != 0) {
    localeIndex = g_pSimMgr->difficultyLevel;
  }
  this->diplomacyBudgetBase = g_anNationBasePressureByLocale[localeIndex] * 100;
  this->escalationCounter =
      static_cast<unsigned char>(g_anGreatPowerEscalationSeedByLocale[localeIndex]);

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    this->tradePolicyByNation[nationIndex] = 0;
    this->diplomacyPolicyByNation[nationIndex] = 0;
    this->diplomacyGrantByNation[nationIndex] = 0;
    this->needCurrentByType[nationIndex] = 0;
    this->needTargetByType[nationIndex] = 0;
    this->relationDeltaCurrent[nationIndex] = 0;
    this->purchasedItemsByResource[nationIndex] = 0;
    this->itemPotentials[nationIndex] = 0;
    this->unfilledTradeTurnCountsByResource[nationIndex] = 0;
    this->transportedItemsByResource[nationIndex] = 0;
    this->rememberedTradeOffersByResource[nationIndex] = 0;
    this->colonyBoycottFlags[nationIndex] = 0;
    for (int matrixRow = 0; matrixRow < 16; ++matrixRow) {
      this->aidAllocationMatrix[nationIndex + matrixRow * kNationSlotCount] = 0;
    }
  }

  for (int pendingIndex = 0; pendingIndex < 13; ++pendingIndex) {
    this->pendingActionStatus.byAction[pendingIndex] = 0;
    this->pendingActionPayload[pendingIndex] = -1;
  }

  int trackedIndex = 0;
  while (trackedIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[trackedIndex] = 0;
    ++trackedIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004d8bc0
void TGreatPower::AssessExpansion(void) {}

// FUNCTION: IMPERIALISM 0x004d8be0
void TGreatPower::ReassessMissions(int unused) {}

// FUNCTION: IMPERIALISM 0x004d8c00
short TGreatPower::GetMerchantCapacity(void) {
  return availableMerchantCapacity;
}

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::IGreatPower(short nationSlotIndex, short humanControlledFlag) {
  InitializeIdentity(nationSlotIndex);

  treasuryValue = g_anNationStartingTreasuryByLocale[g_pSimMgr->difficultyLevel];

  diplomacyEligibility = (humanControlledFlag == 1) ? 1 : 0;

  TCity* cityModel = new TCity();
  if (cityModel != 0) {
    cityModel->ICity(this);
  }
  city = cityModel;

  townMarkerList = new TList();

  grantTotalCost = 0;
  transportCapacity = 0x0F;
  armyTransportRemaining = 0x0F;

  turnEventQueue = new TPtrList();
  turnEventQueue->recordSize = 4;

  proposalQueue = new TPtrList();
  proposalQueue->recordSize = 4;

  if (diplomacyEligibility != 0) {
    TForeignMinister* foreignMinister = new TForeignMinister();
    foreignMinister->IForeignMinister(this);
    this->foreignMinister = foreignMinister;

    TCityInteriorMinister* interiorMinister = new TCityInteriorMinister();
    interiorMinister->InitializeCityInteriorState(this);
    this->interiorMinister = interiorMinister;

    TDefenseMinister* defenseMinister = new TDefenseMinister();
    defenseMinister->IDefenseMinister(this);
    this->defenseMinister = defenseMinister;
  }

  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    TPtrList* trackedSlotList = new TPtrList();
    trackedSlotList->recordSize = 0x0C;
    diplomacyTrackedSlots[listIndex] = trackedSlotList;
    ++listIndex;
  }

  short* diplomacyNeedState = diplomacyPolicyByNation;
  short* diplomacyGrantState = diplomacyGrantByNation;
  unsigned char* diplomacyFlags = colonyBoycottFlags;
  int nationSlot = 0;
  while (nationSlot < kNationSlotCount) {
    diplomacyNeedState[nationSlot] = -1;
    diplomacyGrantState[nationSlot] = -1;
    diplomacyFlags[nationSlot] = 0;
    ++nationSlot;
  }

  trackedObjectList = new TList();

  int candidateIndex = 0;
  while (candidateIndex < kNationSlotCount) {
    enemyFlags[candidateIndex] = 0;
    ++candidateIndex;
  }
  turnFinished = 1;

  turnSummaryQueue = new TPtrList();
  turnSummaryQueue->recordSize = 8;

  turnStartEvents = new TList();
  militaryExpenses = 0;
}

// FUNCTION: IMPERIALISM 0x004d9160
void TGreatPower::Free(void) {
  if (city != 0) {
    city->Free();
  }
  city = 0;
  if (turnEventQueue != 0) {
    turnEventQueue->FreeList();
  }
  turnEventQueue = 0;
  if (proposalQueue != 0) {
    proposalQueue->FreeList();
  }
  proposalQueue = 0;
  if (foreignMinister != 0) {
    foreignMinister->Free();
  }
  foreignMinister = 0;
  if (interiorMinister != 0) {
    interiorMinister->Free();
  }
  interiorMinister = 0;
  if (defenseMinister != 0) {
    defenseMinister->Free();
  }
  defenseMinister = 0;
  TPtrList** trackedSlots = diplomacyTrackedSlots;
  for (int trackedSlotCount = 0; trackedSlotCount < 17; ++trackedSlotCount) {
    if (*trackedSlots != 0) {
      (*trackedSlots)->FreeList();
    }
    *trackedSlots = 0;
    ++trackedSlots;
  }
  if (townMarkerList != 0) {
    townMarkerList->FreeList();
  }
  townMarkerList = 0;
  if (trackedObjectList != 0) {
    trackedObjectList->FreeList();
  }
  trackedObjectList = 0;
  if (turnSummaryQueue != 0) {
    turnSummaryQueue->FreeList();
  }
  turnSummaryQueue = 0;
  if (turnStartEvents != 0) {
    turnStartEvents->FreeList();
  }
  turnStartEvents = 0;
  if (militaryUnitList != 0) {
    militaryUnitList->FreeList();
  }
  militaryUnitList = 0;
  if (ownedRegionList != 0) {
    ownedRegionList->Free();
    ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d92e0
void TGreatPower::ReadFrom(TStream* stream) {
  TCountry::ReadFrom(stream);
  stream->ReadBytes(&diplomacyEligibility, 1);
  stream->ReadBytes(&availableMerchantCapacity, 2);
  stream->ReadBytes(&merchantCapacity, 2);
  stream->ReadBytes(&transportCapacity, 2);
  stream->ReadBytes(&reservedTransportCapacity, 2);
  if (g_nSaveFormatVersion < 0x3E) {
    stream->ReadBytes(&grantTotalCost, 2);
  } else {
    stream->ReadBytes(&grantTotalCost, 4);
  }
  stream->ReadBytes(&unfilledTradeOfferCount, 2);
  stream->ReadBytes(diplomacyPolicyByNation, 46);
  SwapShortArrayBytes(diplomacyPolicyByNation, kNationSlotCount);
  stream->ReadBytes(diplomacyGrantByNation, 46);
  SwapShortArrayBytes(diplomacyGrantByNation, kNationSlotCount);
  stream->ReadBytes(needCurrentByType, sizeof(needCurrentByType));
  SwapShortArrayBytes(needCurrentByType, kResourceKindCount);
  stream->ReadBytes(needTargetByType, sizeof(needTargetByType));
  SwapShortArrayBytes(needTargetByType, kResourceKindCount);
  stream->ReadBytes(relationDeltaCurrent, sizeof(relationDeltaCurrent));
  SwapShortArrayBytes(relationDeltaCurrent, kResourceKindCount);
  stream->ReadBytes(purchasedItemsByResource, sizeof(purchasedItemsByResource));
  SwapShortArrayBytes(purchasedItemsByResource, kResourceKindCount);
  stream->ReadBytes(itemPotentials, sizeof(itemPotentials));
  SwapShortArrayBytes(itemPotentials, kResourceKindCount);

  if (g_nSaveFormatVersion >= 0x17) {
    stream->ReadBytes(unfilledTradeTurnCountsByResource, sizeof(unfilledTradeTurnCountsByResource));
    SwapShortArrayBytes(unfilledTradeTurnCountsByResource, kResourceKindCount);
  }

  stream->ReadBytes(transportedItemsByResource, sizeof(transportedItemsByResource));
  SwapShortArrayBytes(transportedItemsByResource, kResourceKindCount);
  stream->ReadBytes(rememberedTradeOffersByResource, sizeof(rememberedTradeOffersByResource));
  SwapShortArrayBytes(rememberedTradeOffersByResource, kResourceKindCount);

  stream->ReadBytes(&budgetPoolBase, 4);
  stream->ReadBytes(&budgetPoolDelta, 4);
  stream->ReadBytes(aidAllocationMatrix, 1472);
  ReverseDwordArrayBytes(aidAllocationMatrix, 0x170);

  stream->ReadBytes(&pendingActionStatus, sizeof(pendingActionStatus));
  stream->ReadBytes(pendingActionPayload, 26);
  SwapShortArrayBytes(pendingActionPayload, 13);

  turnEventQueue->ReadFrom(stream);
  proposalQueue->ReadFrom(stream);
  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    diplomacyTrackedSlots[listIndex]->ReadFrom(stream);
    ++listIndex;
  }

  if (g_nSaveFormatVersion < 0x1D) {
    if (encodedNationSlot == -1) {
      bool remote = IsRemote();
      if (!remote) {
        foreignMinister->ReadFrom(stream);
        interiorMinister->ReadFrom(stream);
        defenseMinister->ReadFrom(stream);
      }
      city->ReadFrom(stream);
    } else {
      // Each `= 0` sits after its free-if, not inside it (0x4d9621 and friends).
      if (foreignMinister != 0) {
        foreignMinister->Free();
      }
      foreignMinister = 0;
      if (interiorMinister != 0) {
        interiorMinister->Free();
      }
      interiorMinister = 0;
      if (defenseMinister != 0) {
        defenseMinister->Free();
      }
      defenseMinister = 0;
      if (city != 0) {
        city->Free();
      }
      city = 0;
    }
  } else {
    char ministerMask = stream->ReadByte();

    if ((ministerMask & 1) != 0) {
      if (foreignMinister == 0) {
        TForeignMinister* created = new TForeignMinister();
        foreignMinister = created;
        created->IForeignMinister(this);
      }
      foreignMinister->ReadFrom(stream);
    } else {
      if (foreignMinister != 0) {
        foreignMinister->Free();
      }
      foreignMinister = 0;
    }

    if ((ministerMask & 2) != 0) {
      if (interiorMinister == 0) {
        TCityInteriorMinister* created = new TCityInteriorMinister();
        interiorMinister = created;
        created->InitializeCityInteriorState(this);
      }
      interiorMinister->ReadFrom(stream);
    } else {
      if (interiorMinister != 0) {
        interiorMinister->Free();
      }
      interiorMinister = 0;
    }

    if ((ministerMask & 4) != 0) {
      if (defenseMinister == 0) {
        TDefenseMinister* created = new TDefenseMinister();
        defenseMinister = created;
        created->IDefenseMinister(this);
      }
      defenseMinister->ReadFrom(stream);
    } else {
      if (defenseMinister != 0) {
        defenseMinister->Free();
      }
      defenseMinister = 0;
    }

    if ((ministerMask & 8) != 0) {
      city->ReadFrom(stream);
    } else {
      if (city != 0) {
        city->Free();
      }
      city = 0;
    }
  }

  if (townMarkerList->GetCount() != 0) {
    townMarkerList->FreePayloads();
  }
  townMarkerList->ReadFrom(stream);

  int entryCount;
  stream->ReadBytes(&entryCount, 4);
  for (int townOrdinal = 1; townOrdinal <= entryCount; ++townOrdinal) {
    TTown* townMarker = new TTown();
    townMarker->ReadFrom(stream);
    townMarkerList->AddTail(townMarker);
  }

  if (entryCount > 0 && city != NULL) {
    city->SetSelectedTownMarker(static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(1)));
  }

  if (trackedObjectList->GetCount() != 0) {
    trackedObjectList->FreePayloads();
  }
  trackedObjectList->ReadFrom(stream);

  stream->ReadBytes(&entryCount, 4);
  for (int orderOrdinal = 1; orderOrdinal <= entryCount; ++orderOrdinal) {
    TCivUnit* civOrderObj = new TCivUnit();
    civOrderObj->ICivUnit(kCivilianUnitMiner, -1, nationSlot);
    civOrderObj->ReadFrom(stream);
  }

  stream->ReadBytes(enemyFlags, 23);

  stream->ReadBytes(&diplomacyBudgetBase, 4);
  stream->ReadBytes(&escalationCounter, 1);
  stream->ReadBytes(&pendingCommitmentCost, 4);
  stream->ReadBytes(&pressureCounter, 1);
  stream->ReadBytes(&armyTransportRemaining, 4);
  stream->ReadBytes(&turnFinished, 1);

  if (g_nSaveFormatVersion > 0x0E) {
    turnStartEvents->ReadFrom(stream);

    int eventCount = 0;
    stream->ReadBytes(&eventCount, 4);
    for (int eventOrdinal = 1; eventOrdinal <= eventCount; ++eventOrdinal) {
      TTurnStartEvent* event = 0;
      if (stream->ReadObject(&event)) {
        turnStartEvents->AddTail(event);
      }
    }
  }

  if (g_nSaveFormatVersion >= 0x26) {
    stream->ReadBytes(&specialResourceTradeBalance, 4);
    stream->ReadBytes(&aidAllocationTotal, 4);
  }
  if (g_nSaveFormatVersion > 0x2F) {
    stream->ReadBytes(colonyBoycottFlags, kNationSlotCount);
  }
  if (g_nSaveFormatVersion > 0x34) {
    stream->ReadBytes(&militaryExpenses, 4);
  }
}

// FUNCTION: IMPERIALISM 0x004d9c70
void TGreatPower::WriteTo(TStream* stream) {
  TCountry::WriteTo(stream);

  stream->WriteBytes(&diplomacyEligibility, 1);
  stream->WriteBytes(&availableMerchantCapacity, 2);
  stream->WriteBytes(&merchantCapacity, 2);
  stream->WriteBytes(&transportCapacity, 2);
  stream->WriteBytes(&reservedTransportCapacity, 2);
  stream->WriteBytes(&grantTotalCost, 4);
  stream->WriteBytes(&unfilledTradeOfferCount, 2);

  WriteShortArrayElems(stream, diplomacyPolicyByNation, 23);
  WriteShortArrayElems(stream, diplomacyGrantByNation, 23);
  WriteShortArrayElems(stream, needCurrentByType, kResourceKindCount);
  WriteShortArrayElems(stream, needTargetByType, kResourceKindCount);
  WriteShortArrayElems(stream, relationDeltaCurrent, kResourceKindCount);
  WriteShortArrayElems(stream, purchasedItemsByResource, kResourceKindCount);
  WriteShortArrayElems(stream, itemPotentials, kResourceKindCount);
  WriteShortArrayElems(stream, unfilledTradeTurnCountsByResource, kResourceKindCount);
  WriteShortArrayElems(stream, transportedItemsByResource, kResourceKindCount);
  WriteShortArrayElems(stream, rememberedTradeOffersByResource, kResourceKindCount);

  stream->WriteBytes(&budgetPoolBase, 4);
  stream->WriteBytes(&budgetPoolDelta, 4);
  WriteIntArrayElems(stream, aidAllocationMatrix, 0x170);

  stream->WriteBytes(&pendingActionStatus, sizeof(pendingActionStatus));
  WriteShortArrayElemsRev(stream, pendingActionPayload, 0xd);

  turnEventQueue->WriteTo(stream);
  proposalQueue->WriteTo(stream);
  for (int slotIndex = 0; slotIndex < kDiplomacyTrackedSlotCount; ++slotIndex) {
    diplomacyTrackedSlots[slotIndex]->WriteTo(stream);
  }

  unsigned char presenceFlags = 0;
  if (foreignMinister != 0) {
    presenceFlags = 1;
  }
  if (interiorMinister != 0) {
    presenceFlags |= 2;
  }
  if (defenseMinister != 0) {
    presenceFlags |= 4;
  }
  if (city != 0) {
    presenceFlags |= 8;
  }
  stream->WriteByte(presenceFlags);
  if (foreignMinister != 0) {
    foreignMinister->WriteTo(stream);
  }
  if (interiorMinister != 0) {
    interiorMinister->WriteTo(stream);
  }
  if (defenseMinister != 0) {
    defenseMinister->WriteTo(stream);
  }
  if (city != 0) {
    city->WriteTo(stream);
  }

  townMarkerList->WriteTo(stream);
  {
    int entryCount = townMarkerList->GetCount();
    stream->WriteBytes(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      TUnit* entry = static_cast<TUnit*>(townMarkerList->GetEntryByOrdinal(ordinal));
      entry->WriteTo(stream);
    }
  }
  trackedObjectList->WriteTo(stream);
  {
    int entryCount = trackedObjectList->GetCount();
    stream->WriteBytes(&entryCount, 4);
    for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
      TUnit* entry = static_cast<TUnit*>(trackedObjectList->GetEntryByOrdinal(ordinal));
      entry->WriteTo(stream);
    }
  }

  stream->WriteBytes(enemyFlags, 23);
  stream->WriteBytes(&diplomacyBudgetBase, 4);
  stream->WriteBytes(&escalationCounter, 1);
  stream->WriteBytes(&pendingCommitmentCost, 4);
  stream->WriteBytes(&pressureCounter, 1);
  stream->WriteBytes(&armyTransportRemaining, 4);
  stream->WriteBytes(&turnFinished, 1);

  turnStartEvents->WriteTo(stream);
  int eventCount = turnStartEvents->GetCount();
  stream->WriteBytes(&eventCount, 4);
  for (int eventOrdinal = 1; eventOrdinal <= eventCount; ++eventOrdinal) {
    TTurnStartEvent* event =
        static_cast<TTurnStartEvent*>(turnStartEvents->GetEntryByOrdinal(eventOrdinal));
    stream->WriteObject(event, 0);
  }

  stream->WriteBytes(&specialResourceTradeBalance, 4);
  stream->WriteBytes(&aidAllocationTotal, 4);
  stream->WriteBytes(colonyBoycottFlags, 23);
  stream->WriteBytes(&militaryExpenses, 4);
}

// FUNCTION: IMPERIALISM 0x004da3e0
void TGreatPower::MultiReadFrom(TStream* stream, int unusedArg) {
  TCountry::MultiReadFrom(stream, unusedArg);

  if (trackedObjectList->GetCount() != 0) {
    trackedObjectList->FreePayloads();
  }
  trackedObjectList->ReadFrom(stream);

  int orderCount = stream->ReadInteger();
  for (; orderCount > 0; --orderCount) {
    TCivUnit* civOrder = new TCivUnit();
    civOrder->ICivUnit(kCivilianUnitMiner, -1, nationSlot);
    civOrder->ReadFrom(stream);
  }
}

// FUNCTION: IMPERIALISM 0x004da500
void TGreatPower::MultiWriteTo(TStream* stream) {
  TCountry::MultiWriteTo(stream);

  trackedObjectList->WriteTo(stream);
  int orderCount = trackedObjectList->GetCount();
  stream->WriteInteger(orderCount);
  for (int ordinal = 1; ordinal <= orderCount; ++ordinal) {
    TUnit* order = static_cast<TUnit*>(trackedObjectList->GetEntryByOrdinal(ordinal));
    order->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x004da5c0
void TGreatPower::NoOpNationPendingActionHook(void) {}

// FUNCTION: IMPERIALISM 0x004da5e0
void TGreatPower::DispatchPendingStatusPrompts(void) {
  signed char* flags = pendingActionStatus.byAction;
  bool flag5Handled = (flags[5]) >= 0x33;
  if (!flag5Handled && g_pTechMgr->orderCapRows277[nationSlot].techStatusByTechId[15] == 2) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(5, pendingActionPayload[5]);
  }
  if (flags[6] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(6, pendingActionPayload[6]);
  }
  if (flags[7] == 0x32) {
    if (pendingActionPayload[7] == 2) {
      TCity* cityPtr = city;
      cityPtr->stockByType[kResourcePaper] += 10;
      cityPtr->VerifyStocks();
      g_pViewMgr->BuildAndShowTurnOverlayByMode(7, pendingActionPayload[7]);
    } else if (pendingActionPayload[7] == 3) {
      TCity* cityPtr = city;
      cityPtr->stockByType[kResourcePaper] += 10;
      cityPtr->VerifyStocks();
      g_pViewMgr->BuildAndShowTurnOverlayByMode(7, -1);
    }
  }
  if (flags[8] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(8, pendingActionPayload[8]);
  }
  if (flags[9] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(9, pendingActionPayload[9]);
  }
  if (flags[10] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(10, pendingActionPayload[10]);
  }
  if (flags[11] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(11, pendingActionPayload[11]);
  }
  if (flags[12] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(12, pendingActionPayload[12]);
  }
  if (flags[0] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(0, g_pTechMgr->activeZoneIndex);
  }
  if (flags[1] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(1, pendingActionPayload[1]);
  }
  if (flags[2] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(2, pendingActionPayload[2]);
  }
  if (flags[3] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(3, pendingActionPayload[3]);
  }
  if (flags[4] == 0x32) {
    g_pViewMgr->BuildAndShowTurnOverlayByMode(4, pendingActionPayload[4]);
  }
}

// FUNCTION: IMPERIALISM 0x004da860
void TGreatPower::MarkStatus5Handled(void) {
  if (g_pTechMgr->orderCapRows277[nationSlot].techStatusByTechId[15] == 2) {
    pendingActionStatus.byAction[5] = 0x33;
  }
}

// FUNCTION: IMPERIALISM 0x004da8a0
void TGreatPower::MarkAllPendingStatusFlagsHandled(void) {
  signed char* flags = pendingActionStatus.byAction;
  bool flag5Handled = (flags[5]) >= 0x33;
  if (!flag5Handled && g_pTechMgr->orderCapRows277[nationSlot].techStatusByTechId[15] == 2) {
    flags[5] = 0x33;
  }
  if (flags[6] == 0x32) {
    flags[6] = 0x33;
  }
  if (flags[7] == 0x32) {
    if (pendingActionPayload[7] == 2) {
      flags[7] = 0x33;
    } else if (pendingActionPayload[7] == 3) {
      flags[7] = 0x34;
      pendingActionPayload[7] = -1;
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
    flags[0] = static_cast<unsigned char>(static_cast<char>(pendingActionPayload[0]) + 0x33);
  }
  if (flags[1] == 0x32) {
    flags[1] = static_cast<unsigned char>(static_cast<char>(pendingActionPayload[1]) + 0x33);
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
    pendingActionStatus.byAction[index] = 0x32;
    pendingActionPayload[index] = payload;
  }
}

// FUNCTION: IMPERIALISM 0x004daa50
void TGreatPower::AddTurnStartEvent(TTurnStartEvent* event) {
  turnStartEvents->AddTail(event);
}

// FUNCTION: IMPERIALISM 0x004daa80
void TGreatPower::DisplayTurnStartEvents() {
  CIterator eventIter(turnStartEvents);
  for (TTurnStartEvent* event = static_cast<TTurnStartEvent*>(eventIter.Reset()); eventIter.More();
       event = static_cast<TTurnStartEvent*>(eventIter.Advance())) {
    event->Execute();
  }
  turnStartEvents->FreePayloads();
}

// FUNCTION: IMPERIALISM 0x004dab00
void TGreatPower::NoOpNationQueuedOrderHook(void) {}

// FUNCTION: IMPERIALISM 0x004dab20
void TGreatPower::ExecuteNationPendingActionStateMachine(void) {
  TCity* cityPtr = city;
  cityPtr->ProduceUnits();

  short nationSlot = this->nationSlot;

  // Land recruit order (pending status 1 == '2').
  if (pendingActionStatus.byAction[1] == 0x32) {
    TMilitaryUnit* militaryOrder = new TMilitaryUnit();
    int nodeContext = GetCapitolProvince();
    short capValue = g_pTechMgr->nationCapRows1e8[nationSlot].slots[9];
    militaryOrder->IMilitaryUnit(capValue, nodeContext, nationSlot);
    AnnounceLater(3, capValue, 1);
  }

  // Navy primary/secondary order (pending status 0 == '2').
  if (pendingActionStatus.byAction[0] == 0x32) {
    short zoneIndex = g_pTechMgr->activeZoneIndex;
    TZone* portZone = g_pActiveMapOrderContext->GetPortZone(nationSlot);
    TShip* primaryOrder = CreateAdmiral(zoneIndex, portZone, nationSlot, 0);

    ++cityPtr->orderCountByType[g_pTechMgr->activeZoneIndex];

    TAdmiral* secondaryNode = new TAdmiral(nationSlot);
    secondaryNode->AssignToShip(primaryOrder);

    AnnounceLater(3, 0x2508, 1);
    AnnounceLater(0, g_pTechMgr->activeZoneIndex, 1);
  }

  // Civil work order (pending status 2 < '3').
  if (pendingActionStatus.byAction[2] < 0x33) {
    bool needsCivOrder = false;
    TCountry** minorEntry = &g_apTerrainTypeDescriptorTable[kMajorNationCount];
    short zoneCursor = 7;
    do {
      if (g_pDiplomacyTurnStateManager
              ->relationStandingScores[zoneCursor + nationSlot * kNationSlotCount] > 0xa9) {
        TCountry* minor = *minorEntry;
        bool ownProtectorate = false;
        if (minor != 0) {
          short ownerTag = minor->encodedNationSlot;
          ownProtectorate =
              ownerTag > 99 && ownerTag < 200 && static_cast<short>(ownerTag - 100) == nationSlot;
        }
        if (!ownProtectorate) {
          needsCivOrder = true;
        }
      }
      ++minorEntry;
      ++zoneCursor;
    } while (minorEntry < &g_apTerrainTypeDescriptorTable[kNationSlotCount]);

    if (needsCivOrder) {
      TCivUnit* civOrder = new TCivUnit();
      civOrder->ICivUnit(kCivilianUnitDeveloper,
                         g_pGlobalMapState->FindRecruitTile(homeTileIndex, false), nationSlot);
      SetNationPendingActionStateAndPayload(2, -1);
    }
  }

  // Final pending-action flush (pending status 0x0a == '2').
  if (pendingActionStatus.byAction[10] == 0x32) {
    city->orderCountByType[6] += 2; // navy secondary-order counter
    AnnounceLater(1, 6, 2);
  }
  NameUnits();
}

// FUNCTION: IMPERIALISM 0x004dae70
bool TGreatPower::HasDeveloper(void) {
  bool found = false;
  CIterator orderIter(trackedObjectList);
  TUnit* order = static_cast<TUnit*>(orderIter.Reset());
  if (orderIter.More()) {
    while (order->orderType != EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
      order = static_cast<TUnit*>(orderIter.Advance());
      if (!orderIter.More()) {
        return false;
      }
    }
    found = true;
  }
  return found;
}

// FUNCTION: IMPERIALISM 0x004daf00
void TGreatPower::SorryYouLose(void) {
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
}

// FUNCTION: IMPERIALISM 0x004daf30
void TGreatPower::SellStockToCoverDebt(void) {
  int liquidationOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                            0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (IsRemote()) {
    return;
  }

  int pressureThreshold = g_anDebtLiquidationThresholdByDifficulty[g_pSimMgr->difficultyLevel];
  if (pressureThreshold > static_cast<int>(pressureCounter)) {
    return;
  }

  int soldAmountByResource[kResourceKindCount];
  for (int idx = 0; idx < 23; ++idx) {
    soldAmountByResource[idx] = 0;
  }

  CString summaryMessageRef;

  int proceeds = 0;

  int* resourceCursor = liquidationOrder;
  while (*resourceCursor != -1) {
    if (proceeds + treasuryValue >= 0) {
      break;
    }

    short resourceKind = *resourceCursor;
    TCity* city = this->city;
    short* stock = city->stockByType + resourceKind;
    short soldAmount = *stock;
    if (soldAmount > 0) {
      *stock = 0;
      soldAmountByResource[resourceKind] = static_cast<int>(soldAmount);

      city->VerifyStocks();

      int price = g_pTradeMgr->GetPrice(resourceKind);
      proceeds = static_cast<int>(static_cast<float>(proceeds) -
                                  static_cast<float>(price * soldAmount) * (-0.25f));

      if (summaryMessageRef != "") {
        summaryMessageRef += g_szListSeparator;
      }

      CString amountText;
      amountText.Format(g_szDecimalFormat, static_cast<int>(soldAmount));
      summaryMessageRef += amountText + s_szSpaceSeparator;

      CString commodityName;
      g_pSimMgr->GetCommodityName(resourceKind, &commodityName);
      summaryMessageRef += commodityName;
    }

    ++resourceCursor;
  }

  AddToTreasury(proceeds);

  if (proceeds > 0) {
    CString headerText;
    CString currencyText;
    g_pSimMgr->GetString(0x274b, 0, &headerText);
    g_pSimMgr->NumToCurrency(proceeds, &currencyText);
    headerText += currencyText + ": \n";
    summaryMessageRef += headerText;
    g_pViewMgr->ModalMessage(summaryMessageRef, g_ptGreatPowerModalMessage, 2, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004db380
bool TGreatPower::CheckBankruptcy(void) {
  TSimMgr* simMgr = g_pSimMgr;
  int localeIndex = 0;
  if (simMgr != 0) {
    localeIndex = simMgr->difficultyLevel;
  }

  int treasuryValue = this->treasuryValue;
  int basePressure = GetTotalOverseasProfits();
  basePressure += static_cast<int>(needTargetByType[kResourceGold]) * 200;
  basePressure += static_cast<int>(needTargetByType[kResourceGems]) * 500;
  basePressure += budgetPoolBase;
  int pressureFloor = g_anNationBasePressureByLocale[localeIndex];
  if (basePressure < pressureFloor) {
    basePressure = pressureFloor;
  }

  int smoothedPressure = (diplomacyBudgetBase * 90 + basePressure * 1000) / 100;
  diplomacyBudgetBase = smoothedPressure;
  int pressureBand = smoothedPressure / 100;

  if (treasuryValue < 0) {
    int halfBand = pressureBand / 2;
    if (-treasuryValue <= halfBand) {
      pressureCounter = 1;
    } else if (-treasuryValue <= pressureBand) {
      if (pressureCounter > 1) {
        int nextPressureValue =
            escalationCounter +
            static_cast<signed char>(g_anGreatPowerPressureRiseStepByLocale[localeIndex]);
        int pressureRiseCap = g_anGreatPowerPressureRiseCapByLocale[localeIndex];
        if (nextPressureValue > pressureRiseCap) {
          nextPressureValue = pressureRiseCap;
        }
        escalationCounter = static_cast<signed char>(nextPressureValue);
      }
      pressureCounter = 2;
    } else {
      CString sharedMessageRef;
      int nextPressureValue =
          escalationCounter +
          static_cast<signed char>(g_anGreatPowerPressureRiseStepByLocale[localeIndex]);
      int pressureRiseCap = g_anGreatPowerPressureRiseCapByLocale[localeIndex];
      if (nextPressureValue > pressureRiseCap) {
        nextPressureValue = pressureRiseCap;
      }
      escalationCounter = static_cast<signed char>(nextPressureValue);

      if (pressureCounter < 3) {
        pressureCounter = 3;
      } else {
        pressureCounter = static_cast<signed char>(pressureCounter + 1);
      }

      int pressureTier = pressureCounter;
      if (pressureTier >= g_anGreatPowerPressureHardAlertThresholdByLocale[localeIndex]) {
        g_pSimMgr->GetString(0x274b, 4, &sharedMessageRef);
        g_pViewMgr->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
        return true;
      }

      int compileThreshold = g_anDebtLiquidationThresholdByDifficulty[localeIndex];
      if (pressureTier >= compileThreshold) {
        g_pSimMgr->GetString(0x274b, 1, &sharedMessageRef);
        g_pViewMgr->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
        SellStockToCoverDebt();
      } else if (pressureTier == (compileThreshold - 1)) {
        g_pSimMgr->GetString(0x274b, 3, &sharedMessageRef);
        g_pViewMgr->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
      } else {
        g_pSimMgr->GetString(0x274b, 2, &sharedMessageRef);
        g_pViewMgr->ModalMessage(sharedMessageRef, g_ptGreatPowerModalMessage, 2, 0);
      }
    }
  } else {
    if (pressureCounter != 0) {
      int nextPressureValue =
          escalationCounter -
          static_cast<signed char>(g_anGreatPowerPressureDecayStepByLocale[localeIndex]);
      int pressureMinFloor = g_anGreatPowerPressureMinFloorByLocale[localeIndex];
      if (nextPressureValue < pressureMinFloor) {
        nextPressureValue = pressureMinFloor;
      }
      escalationCounter = static_cast<signed char>(nextPressureValue);
      pressureCounter = 0;
    }
  }

  treasuryValue = this->treasuryValue;
  if (treasuryValue >= 0) {
    pendingCommitmentCost = 0;
    return false;
  }

  int drainAmount = (0xC7 - static_cast<int>(escalationCounter) * treasuryValue) / 200;
  pendingCommitmentCost = drainAmount;
  this->treasuryValue = treasuryValue - drainAmount;
  return false;
}
