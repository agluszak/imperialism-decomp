#include "game/TCountry.h"

#include "game/CString.h"
#include "game/global_data_tables.h"
#include "game/TGreatPower.h"

#include "game/TInterNationEventQueueManager.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TOcean.h"
#include "game/TMilitaryUnit.h"
#include "game/TMilitaryUnitOrderState.h"
#include "game/TMilitaryUnit.h"
#include "game/TStream.h"
#include "game/TShip.h"
#include "game/TUnit.h"
#include "game/TZone.h"
#include "game/nation_slot_eligibility.h"
#include "game/nation_stream_serialization.h"
#include "game/TMultiplayerMgr.h"
#include "game/mapped_flavor_text.h"

#include "game/TDiplomacyMgr.h"
#include "game/TInterNationEventQueueManager.h"

#include <new>

extern char g_szEmptyString[];

undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

static const unsigned int kAddrClassDescTCountry = 0x00653670;

static __inline bool IsRecruitQuarterTickGate(short tickRaw) {
  int tick = static_cast<int>(tickRaw);
  int quarterIndex = (tick + ((tick >> 0x1f) & 3)) >> 2;
  if ((quarterIndex & 1) == 0) {
    return 0;
  }
  int sign = tick >> 0x1f;
  int mod4 = tick;
  mod4 ^= sign;
  mod4 -= sign;
  mod4 &= 3;
  mod4 ^= sign;
  mod4 -= sign;
  return static_cast<short>(mod4) == 2;
}

static void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

static const unsigned int kAddrWeightedNeighborScoreByUnitType = 0x006955F0;

// FUNCTION: IMPERIALISM 0x004a5aa0
int ComputeWeightedNeighborLinkScoreForNodeIndex(short nodeIndex) {
  if (nodeIndex < 0 || nodeIndex > 0x17f) {
    return 0;
  }
  TMilitaryUnit* chain = g_pGlobalMapState->cityScoreTable[nodeIndex].stationedUnitChain98;
  int sum = 0;
  for (; chain != 0; chain = chain->next14) {
    sum += *reinterpret_cast<int*>(kAddrWeightedNeighborScoreByUnitType + chain->unitTypeId04 * 4);
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004d6730
char TCountry::ReturnFalseNationStateCapabilityFlag98(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d6750
char TCountry::ReturnFalseNationStateCapabilityFlag9C(void) {
  return 0;
}

// slot 0x28 — ShouldDispatchImmediatelySlot28 (real body).
// FUNCTION: IMPERIALISM 0x004d6770
char TCountry::ShouldDispatchImmediatelySlot28(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d6790
void TCountry::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}
// SYNTHETIC: IMPERIALISM 0x004d66a0
// TCountry::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d67b0
// TCountry::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCountry, TObject)

TCountry::TCountry() {}

// SYNTHETIC: IMPERIALISM 0x004d6850
// TCountry::`scalar deleting destructor'
TCountry::~TCountry() {}

// FUNCTION: IMPERIALISM 0x004d68f0
void TCountry::InitializeNationStateIdentityAndOwnedRegionList(short nationSlot) {
  this->nationSlot = nationSlot;
  this->ownerNationSlot = -1;
  this->serializedField8c = -1;
  this->encodedNationSlot = -1;

  int dwordIndex = 0;
  do {
    *reinterpret_cast<int*>(&this->needLevelByNation[dwordIndex * 2]) = 0x640064;
    ++dwordIndex;
  } while (dwordIndex < 0xb);
  this->needLevelByNation[0x16] = 100;

  this->identitySharedString0 = g_szEmptyString;
  CString flavorName;
  SetSharedStringFromMappedFlavorTextWithLengthClamp(&flavorName, nationSlot);
  this->identitySharedString0 = flavorName;
  if (g_pLocalizationTable != 0) {
    CString* nationNameSlot = reinterpret_cast<CString*>(
        reinterpret_cast<char*>(g_pLocalizationTable) + nationSlot * 4 + 0x7c);
    *nationNameSlot = this->identitySharedString0;
  }
  this->identitySharedString1 = this->identitySharedString0;
  this->treasuryValue10 = 5000;

  this->militaryUnitList44 = new TSortedList();

  int ordinalIndex = 0;
  do {
    *reinterpret_cast<int*>(&this->unitNameOrdinalByType[ordinalIndex * 2]) = 0x10001;
    ++ordinalIndex;
  } while (ordinalIndex < 0xf);
  this->unitNameCounter84 = 1;

  TSortedList* ownedRegions = new TSortedList();
  for (int cityIndex = 0; cityIndex < 0x180; ++cityIndex) {
    if (static_cast<short>(g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00) ==
        nationSlot) {
      ownedRegions->AddTailSlot34(reinterpret_cast<void*>(cityIndex));
    }
  }
  this->ownedRegionList = ownedRegions;
}

// FUNCTION: IMPERIALISM 0x004d6ba0
void TCountry::Free(void) {
  if (this->militaryUnitList44 != 0) {
    this->militaryUnitList44->FreePayloadsAndDestroySlot58();
  }
  this->militaryUnitList44 = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->AddTailSlot38();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d6bf0
void TCountry::ReadFrom(TStream* stream) {
  int streamState = reinterpret_cast<int>(stream);
  stream->streamSlot70();
  stream->streamSlot70();

  CString* nationNameSource = reinterpret_cast<CString*>(
      reinterpret_cast<char*>(g_pLocalizationTable) + this->nationSlot * 4 + 0x7c);
  this->identitySharedString1 = *nationNameSource;
  stream->ReadBytes(&this->identitySharedString0, 4);

  stream->ReadBytes(&this->nationSlot, 2);
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(this->unitNameOrdinalByType, 0x3c);
  SwapAdjacentBytesInShortArray(this->unitNameOrdinalByType, 0x1e);

  stream->ReadBytes(&this->unitNameCounter84, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->ownerNationSlot, 4);
  stream->ReadBytes(&this->serializedField8c, 4);
  stream->ReadBytes(this->needLevelByNation, 0x2e);
  SwapAdjacentBytesInShortArray(this->needLevelByNation, 0x17);

  if (this->militaryUnitList44->GetCountSlot48() != 0) {
    this->militaryUnitList44->FreePayloadsSlot54();
  }
  this->militaryUnitList44->ReadFrom(reinterpret_cast<TStream*>(streamState));

  int recruitCount = 0;
  stream->ReadBytes(&recruitCount, 4);
  int recruitIndex = 1;
  if (recruitCount > 0) {
    do {
      TMilitaryUnitOrderState* militaryOrder = new TMilitaryUnitOrderState();
      if (militaryOrder != nullptr) {
        militaryOrder->InitializeRecruitOrderState(0, 0, this->nationSlot);
        militaryOrder->ReadFrom(stream);
      }
      recruitIndex = recruitIndex + 1;
    } while (recruitIndex <= recruitCount);
  }

  if (this->ownedRegionList->GetCountSlot48() != 0) {
    this->ownedRegionList->AddTailSlot38();
  }
  this->ownedRegionList->ShallowClone();
  int regionDeserializeCount = 0;
  stream->ReadBytes(&regionDeserializeCount, 4);
  int regionIndex = 1;
  if (regionDeserializeCount > 0) {
    do {
      int entryValue = 0;
      stream->ReadBytes(&entryValue, 4);
      this->ownedRegionList->WriteTo(stream);
      regionIndex = regionIndex + 1;
    } while (regionIndex <= regionDeserializeCount);
  }
}

// Serializes the TCountry base sub-object: the identity strings (stream slot 0xac), the
// nation-slot metrics, the per-unit-type name ordinals, the military unit list and the
// owned-region list. The leading TObject::WriteTo is the no-op base-of-base (0x00485f70).

// FUNCTION: IMPERIALISM 0x004d6e60
void TCountry::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);

  stream->streamSlotAc(&this->identitySharedString0);
  stream->streamSlotAc(&this->identitySharedString1);

  stream->WriteBytesSlot78(&this->nationSlot, 2);
  stream->WriteBytesSlot78(&this->encodedNationSlot, 2);
  WriteShortArrayElems(stream, this->unitNameOrdinalByType, 0x1e);
  stream->WriteBytesSlot78(&this->unitNameCounter84, 2);
  stream->WriteBytesSlot78(&this->treasuryValue10, 4);
  stream->WriteBytesSlot78(&this->ownerNationSlot, 4);
  stream->WriteBytesSlot78(&this->serializedField8c, 4);
  WriteShortArrayElems(stream, this->needLevelByNation, 0x17);

  WriteTrackedListToStream(stream, this->militaryUnitList44);
  WriteIntListToStream(stream, this->ownedRegionList);
}

// FUNCTION: IMPERIALISM 0x004d7070
void TCountry::ReadCoreFieldsFromStream(TStream* stream, int unusedArg) {
  (void)unusedArg;
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->ownerNationSlot, 4);
  stream->ReadBytes(&this->serializedField8c, 4);
}

// FUNCTION: IMPERIALISM 0x004d70e0
void TCountry::WriteCoreFieldsToStream(TStream* stream) {
  stream->WriteBytesSlot78(&this->encodedNationSlot, 2);
  stream->WriteBytesSlot78(&this->treasuryValue10, 4);
  stream->WriteBytesSlot78(&this->ownerNationSlot, 4);
  stream->WriteBytesSlot78(&this->serializedField8c, 4);
}

// FUNCTION: IMPERIALISM 0x004d71b0
void TCountry::SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void) {
  TSimMgr* localization = g_pLocalizationTable;
  if (localization->stateFlag114 > 0) {
    g_pGlobalMapState->NotifyCityRecordSlot12C(
        g_pGlobalMapState->terrainStateTable[this->ownerNationSlot].cityRecordIndex);
    return;
  }
  int ordinal = 1;
  if (this->ownedRegionList->GetCountSlot48() >= 1) {
    do {
      int regionId = this->ownedRegionList->GetIntByOrdinalSlot24(ordinal);
      short regionTerrainId = g_pGlobalMapState->cityScoreTable[regionId].ownerNationSlot;
      if ((g_pGlobalMapState->terrainStateTable[regionTerrainId].activeFlags1c & 1) != 0) {
        TMilitaryUnitOrderState* order = new TMilitaryUnitOrderState();
        order->InitializeRecruitOrderState(2, regionId, this->nationSlot);
        if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
          order->SetOrderModeSlot34(2, -1);
        }
        order = new TMilitaryUnitOrderState();
        order->InitializeRecruitOrderState(2, regionId, this->nationSlot);
        if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
          order->SetOrderModeSlot34(2, -1);
        }
        order = new TMilitaryUnitOrderState();
        order->InitializeRecruitOrderState(7, regionId, this->nationSlot);
        if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
          order->SetOrderModeSlot34(2, -1);
        }
        g_pGlobalMapState->NotifyCityRecordSlot12C(regionId);
        if (this->nationSlot < 7 &&
            g_apNationStates[this->nationSlot]->diplomacyEligibilityA0 == 0 &&
            g_pLocalizationTable->runtimeSubsystemIndex == 4) {
          order = new TMilitaryUnitOrderState();
          order->InitializeRecruitOrderState(6, regionId, this->nationSlot);
          if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
            order->SetOrderModeSlot34(2, -1);
          }
          order = new TMilitaryUnitOrderState();
          order->InitializeRecruitOrderState(5, regionId, this->nationSlot);
          if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
            order->SetOrderModeSlot34(2, -1);
          }
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          TCity* cityForPort = (nation != 0) ? nation->city : 0;
          void* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(cityForPort);
          CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, static_cast<TZone*>(portZone),
                                                         this->nationSlot, 0);
        }
        if (this->nationSlot < 7) {
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          if (nation->diplomacyEligibilityA0 != 0 &&
              g_pLocalizationTable->runtimeSubsystemIndex == 0) {
            TCity* cityForPort = (nation != 0) ? nation->city : 0;
            TZone* portZone = static_cast<TZone*>(
                g_pActiveMapOrderContext->FindPortZoneBySelectedTile(cityForPort));
            if (portZone->PrimaryZoneHeapCapacity() == 0) {
              void* grownArray = reinterpret_cast<void*(__cdecl*)(void*, int)>(
                  ReallocateHeapBlockWithAllocatorTracking)(portZone->PrimaryZoneHeapData(), 8);
              if (grownArray == 0) {
                portZone->PrimaryZoneHeapData() =
                    static_cast<TZone**>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
                        ReallocateHeapBlockWithAllocatorTracking)(portZone->PrimaryZoneHeapData(),
                                                                  4));
                portZone->PrimaryZoneHeapCapacity() = 1;
              } else {
                portZone->PrimaryZoneHeapData() = static_cast<TZone**>(grownArray);
                portZone->PrimaryZoneHeapCapacity() = 2;
              }
            }
            if (portZone->PrimaryZoneHeapSize() == 0) {
              portZone->PrimaryZoneHeapSize() = 1;
            }
            CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, portZone->PrimaryZoneHeapData()[0],
                                                           this->nationSlot, 0);
          }
        }
      }
      this->CreateMilitaryRecruitOrderForNode(regionId);
      this->CreateMilitaryRecruitOrderForNode(regionId);
      this->CreateMilitaryRecruitOrderForNode(regionId);
      if (g_pLocalizationTable->runtimeSubsystemIndex > 2) {
        this->CreateMilitaryRecruitOrderForNode(regionId);
        if (this->nationSlot >= 7) {
          TMilitaryUnitOrderState* lateOrder = new TMilitaryUnitOrderState();
          lateOrder->InitializeRecruitOrderState(7, regionId, this->nationSlot);
        }
      }
      if (*g_pGlobalMapState->scenarioTagText1c == '+') {
        TMilitaryUnitOrderState* bonusOrder = new TMilitaryUnitOrderState();
        bonusOrder->InitializeRecruitOrderState(2, regionId, this->nationSlot);
        bonusOrder->SetOrderModeSlot34(2, -1);
      }
      ++ordinal;
    } while (ordinal <= this->ownedRegionList->GetCountSlot48());
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}

// FUNCTION: IMPERIALISM 0x004d7ae0
void TCountry::AddToNationMetricAtField10(int amount) {
  this->treasuryValue10 += amount;
}

// FUNCTION: IMPERIALISM 0x004d7b00
char TCountry::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                             int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7b20
void TCountry::ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode) {
  if (g_pLocalizationTable != 0 && g_pLocalizationTable->redrawEnabled == 1) {
    g_pGameFlowState->DispatchJoinEmpireModeEventPacket24_27(this->nationSlot, targetNationSlot,
                                                             mode);
  }

  if (mode == 1) {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNationSlot, 5);
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(targetNationSlot, this->nationSlot, 5);
  }

  if (this->nationSlot < 7) {
    g_pLocalizationTable->DecrementField30Value();
  }

  if (mode == 0) {
    this->SetNationTransferTargetCodeAndNotifyEligiblePeers(targetNationSlot);
    return;
  }
  if (mode == 1) {
    this->ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
    return;
  }
  this->ApplyJoinEmpireMode2FinalizeNationNameState();
}

// FUNCTION: IMPERIALISM 0x004d7c00
void TCountry::SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) {
  this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0 &&
        nationSlot != this->nationSlot && nationSlot != targetNationSlot) {
      TCountry* terrain = g_apTerrainTypeDescriptorTable[nationSlot];
      if (terrain != 0) {
        terrain->SetNationPercentFieldByModeAndDescriptorLinks(this->nationSlot, 100);
      }
    }
  }
  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7c90
void TCountry::ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) {
  this->encodedNationSlot = static_cast<short>(targetNationSlot + 200);
  this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(targetNationSlot), 100);

  int nationSlot = 0;
  do {
    if (IsNationSlotEligibleForEventProcessing(nationSlot) != 0 && nationSlot != this->nationSlot &&
        nationSlot != targetNationSlot) {
      TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
      if (terrainDescriptor != 0) {
        terrainDescriptor->SetNationPercentFieldByModeAndDescriptorLinks(this->nationSlot, 200);
      }
    }
    ++nationSlot;
  } while (nationSlot < kNationSlotCount);

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7d20
char TCountry::IsEncodedNationSlotMinus200Equal(int nationCode) {
  int adjusted = static_cast<int>(static_cast<short>(this->encodedNationSlot)) - 0xc8;
  if (adjusted == nationCode) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7d50
void TCountry::ApplyJoinEmpireMode2FinalizeNationNameState(void) {
  this->identitySharedString0 = this->identitySharedString1;
}

// FUNCTION: IMPERIALISM 0x004d7d70
void TCountry::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  this->ownedRegionList->AddTailSlot34(reinterpret_cast<void*>(regionId));
}

// FUNCTION: IMPERIALISM 0x004d7da0
void TCountry::AddRegionIdToNationOwnedRegionList(int regionId) {
  this->ownedRegionList->AddHeadSlot28(reinterpret_cast<void*>(regionId));
}

// FUNCTION: IMPERIALISM 0x004d7dd0
void TCountry::SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot, int policyCode) {
  short targetNation = static_cast<short>(targetNationSlot);
  if (policyCode == 500 || policyCode != 200) {
    this->needLevelByNation[targetNation] = 100;
    return;
  }
  TCountry* terrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
  short encodedLink = terrain->encodedNationSlot;
  if (encodedLink > 199) {
    this->needLevelByNation[targetNation] =
        this->needLevelByNation[static_cast<short>(encodedLink - 200)];
    return;
  }
  if (encodedLink > 99) {
    this->needLevelByNation[targetNation] =
        this->needLevelByNation[static_cast<short>(encodedLink - 100)];
    return;
  }
  this->needLevelByNation[targetNation] = this->needLevelByNation[terrain->nationSlot];
}

// FUNCTION: IMPERIALISM 0x004d7e90
void TCountry::DecrementDiplomacyCounterA2ByValue(int delta) {
  (void)delta;
}

// FUNCTION: IMPERIALISM 0x004d7ee0
int TCountry::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// slot 0x1d — GetDiplomacyCounterA2 (real body).
// FUNCTION: IMPERIALISM 0x004d7f00
short TCountry::GetDiplomacyCounterA2(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f20
short TCountry::GetDiplomacyExternalStateByTarget(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f40
short TCountry::QueryNationMetricBySlot7C(short metricSlot) {
  (void)metricSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f60
char TCountry::ReturnFalseNationStateCapabilityFlag90(int arg) {
  (void)arg;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f80
void TCountry::NotifyActionSlot94(int sourceNation, int actionCode) {
  (void)sourceNation;
  (void)actionCode;
}

// FUNCTION: IMPERIALISM 0x004d7fa0
void TCountry::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier) {
  (void)resourceIndex;
  (void)delta;
  (void)multiplier;
}

// FUNCTION: IMPERIALISM 0x004d7fc0
bool TCountry::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  (void)targetNationSlot;
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7fe0
void TCountry::QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) {
  (void)proposalCode;
  (void)targetNationId;
}

// FUNCTION: IMPERIALISM 0x004d8000
void TCountry::AssignDisplayNamesToUnnamedMilitaryUnits(void) {
  int ordinal = 1;
  if (this->militaryUnitList44->GetCountSlot48() < 1) {
    return;
  }
  do {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(this->militaryUnitList44->GetEntryByOrdinalSlot4C(ordinal));
    if (unit->nameTag1a == 0) {
      if (unit->unitTypeId04 < 0x1b) {
        CString ordinalText;
        CString typeName;
        CString composedName;
        short unitType = unit->unitTypeId04;
        TSimMgr* localization = g_pLocalizationTable;
        short* nameOrdinalCounter = &this->unitNameOrdinalByType[unitType];
        localization->FormatOrdinalString(*nameOrdinalCounter, &ordinalText);
        localization->GetString(0x2717, unitType, &typeName);
        CString withSeparator = ordinalText + CString(" ");
        CString fullName = withSeparator + typeName;
        composedName = fullName;
        unit->displayName24 = composedName;
        unit->nameTag1a = this->unitNameCounter84;
        ++this->unitNameCounter84;
        ++*nameOrdinalCounter;
      } else {
        CString flavorBase;
        CString flavorName;
        g_pLocalizationTable->GetString(0x2744, 0, &flavorBase);
        do {
          GenerateMappedFlavorTextByTableSlot(&flavorName, this->nationSlot);
        } while (flavorName.GetLength() > 0xf - flavorBase.GetLength());
        CString withSeparator = flavorBase + CString(" ");
        CString fullName = withSeparator + flavorName;
        flavorName = fullName;
        unit->displayName24 = flavorName;
        unit->nameTag1a = this->unitNameCounter84;
        ++this->unitNameCounter84;
      }
    }
    ++ordinal;
    ordinal = static_cast<short>(ordinal);
  } while (ordinal <= this->militaryUnitList44->GetCountSlot48());
}

int DecodeTerrainNationSlotFromDescriptor(const TCountry* terrain, short encodedNationSlot) {
  if (encodedNationSlot < 200) {
    if (encodedNationSlot < 100) {
      return terrain->nationSlot;
    }
    return encodedNationSlot - 100;
  }
  return encodedNationSlot - 200;
}

int ResolveTerrainNationSlotFromTarget(int targetNationSlot) {
  const TCountry* terrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
  return DecodeTerrainNationSlotFromDescriptor(terrain, terrain->encodedNationSlot);
}

// FUNCTION: IMPERIALISM 0x004d8390
int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex) {
  return ComputeWeightedNeighborLinkScoreForNodeIndex(static_cast<short>(nodeIndex));
}

// FUNCTION: IMPERIALISM 0x004d83c0
int TCountry::SumWeightedNeighborLinkScoreForLinkedNodes(void) {
  int sum = 0;
  TSortedList* linkedList = this->ownedRegionList;
  if (linkedList == 0) {
    return 0;
  }

  int index = 1;
  int count = linkedList->GetCountSlot48();
  if (count <= 0) {
    return 0;
  }

  do {
    int nodeId = linkedList->GetIntByOrdinalSlot24(index);
    sum += ComputeWeightedNeighborLinkScoreForNodeIndex(static_cast<short>(nodeId));
    ++index;
    count = linkedList->GetCountSlot48();
  } while (index <= count);

  return sum;
}

// FUNCTION: IMPERIALISM 0x004d87b0
int TCountry::GetHomeRegionCityRecordIndex(void) {
  return g_pGlobalMapState->terrainStateTable[this->ownerNationSlot].cityRecordIndex;
}

// FUNCTION: IMPERIALISM 0x004d87e0
void TCountry::QueueRecruitOrdersForUndergarrisonedRegions(void) {
  short tickRaw = g_pLocalizationTable->quarterGateTick2c;
  if (!IsRecruitQuarterTickGate(tickRaw)) {
    return;
  }

  int garrisonThreshold = 3;
  if (static_cast<unsigned short>(this->nationSlot) < 7) {
    garrisonThreshold = 4;
  }

  int regionCount = this->ownedRegionList->GetCountSlot48();
  int ordinal = 1;
  if (ordinal > regionCount) {
    return;
  }
  do {
    short regionId = static_cast<short>(this->ownedRegionList->GetIntByOrdinalSlot24(ordinal));
    short garrisonCount = 0;
    TMilitaryUnit* unitChain;
    if ((regionId < 0) || (0x17f < regionId)) {
      unitChain = 0;
    } else {
      unitChain = *reinterpret_cast<TMilitaryUnit**>(
          reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + 0x98 +
          static_cast<int>(regionId) * 0xa8);
    }
    for (; unitChain != 0; unitChain = unitChain->next14) {
      if (unitChain->GetUnitMovementClassId() == 0) {
        garrisonCount = static_cast<short>(garrisonCount + 1);
      }
    }
    if (garrisonCount < static_cast<short>(garrisonThreshold)) {
      this->CreateMilitaryRecruitOrderForNode(static_cast<int>(regionId));
    }
    ordinal = ordinal + 1;
    regionCount = this->ownedRegionList->GetCountSlot48();
  } while (ordinal <= regionCount);
}

// FUNCTION: IMPERIALISM 0x004d8920
void TCountry::ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) {
  if (nationSlot != this->nationSlot) {
    this->needLevelByNation[nationSlot] = static_cast<short>(resetLevel);
  }
}

// --- Diplomacy cluster (0x4E41C0+) — shape-pass stubs; tail-field bodies use TMinor/TGreatPower tail.

void TCountry::DeserializeDiplomacyNationStateFromStream(TStream* stream) {
  TGreatPower* nation = static_cast<TGreatPower*>(this);
  this->ReadFrom(stream);
  stream->ReadBytes(reinterpret_cast<char*>(nation) + 0x94, 0x2e);
  SwapAdjacentBytesInShortArray(nation->needCurrentByType, 0x17);
  stream->ReadBytes(reinterpret_cast<char*>(nation) + 0xc2, 0x2e);
  SwapAdjacentBytesInShortArray(nation->diplomacyPolicyByNation, 0x17);
  stream->ReadBytes(reinterpret_cast<char*>(nation) + 0xf0, 0x2e);
  SwapAdjacentBytesInShortArray(nation->diplomacyGrantByNation, 0x17);
  stream->ReadBytes(&nation->diplomacyCounterA2, 2);
  stream->ReadBytes(&nation->tradeCapacity, 2);
  stream->ReadBytes(&nation->needCapA6, 2);
  stream->ReadBytes(&nation->needsOverCapFlag, 2);
  stream->ReadBytes(&nation->grantTotalCost, 2);
  stream->ReadBytes(&nation->diplomacyCounterB0, 2);
  stream->ReadBytes(&nation->budgetPoolBase, 2);
  stream->ReadBytes(&nation->budgetPoolDelta, 2);
  stream->ReadBytes(&nation->field8d6[0], 2);
  stream->ReadBytes(&nation->field8d6[1], 2);
  stream->ReadBytes(&nation->field8d6[2], 2);
  stream->ReadBytes(nation->serializedStatusFlags, 8);
  SwapAdjacentBytesInShortArray(reinterpret_cast<short*>(nation->serializedStatusFlags), 4);
}

void TCountry::SerializeDiplomacyNationStateToStream(TStream* stream) {
  TGreatPower* nation = static_cast<TGreatPower*>(this);
  TObject::WriteTo(stream);
  WriteShortArrayElems(stream, nation->needCurrentByType, 0x17);
  WriteShortArrayElems(stream, nation->diplomacyPolicyByNation, 0x17);
  WriteShortArrayElems(stream, nation->diplomacyGrantByNation, 0x17);
  stream->WriteBytesSlot78(&nation->diplomacyCounterA2, 2);
  stream->WriteBytesSlot78(&nation->tradeCapacity, 2);
  stream->WriteBytesSlot78(&nation->needCapA6, 2);
  stream->WriteBytesSlot78(&nation->needsOverCapFlag, 2);
  stream->WriteBytesSlot78(&nation->grantTotalCost, 2);
  stream->WriteBytesSlot78(&nation->diplomacyCounterB0, 2);
  stream->WriteBytesSlot78(&nation->budgetPoolBase, 2);
  stream->WriteBytesSlot78(&nation->budgetPoolDelta, 2);
  stream->WriteBytesSlot78(&nation->field8d6[0], 2);
  stream->WriteBytesSlot78(&nation->field8d6[1], 2);
  stream->WriteBytesSlot78(&nation->field8d6[2], 2);
  WriteShortArrayElems(stream, reinterpret_cast<short*>(nation->serializedStatusFlags), 4);
}

char IsPolicyCodeInSpecialNationPolicySet(short policyCode) {
  return (policyCode > 0xc && policyCode < 0x11) ? 1 : 0;
}

void OrphanLeaf_NoCall_Ins07_004e4630(void) {}

int OrphanLeaf_NoCall_Ins03_004e4660(void) {
  return 0;
}

int OrphanLeaf_NoCall_Ins03_004e4680(void) {
  return 0;
}

char TCountry::IsDiplomacyPolicyAllowedForTargetClassState(short policyCode,
                                                           short targetNationSlot) {
  (void)targetNationSlot;
  if (policyCode <= 0xc || policyCode >= 0x11) {
    return 0;
  }
  TGreatPower* nation = reinterpret_cast<TGreatPower*>(this);
  if (policyCode == nation->field8d6[0]) {
    return nation->field8d6[1] == 0;
  }
  if (policyCode == nation->field8d6[2]) {
    return nation->field8d6[3] == 0;
  }
  return 0;
}

char OrphanCallChain_C2_I27_004e4f50(int arg1, int arg2, int arg3, int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

void TCountry::SetNationTradePolicyValueForTargetAndNotify(short targetNationSlot,
                                                           short policyValue) {
  if (targetNationSlot != this->nationSlot) {
    if (policyValue != this->needLevelByNation[targetNationSlot]) {
      this->needLevelByNation[targetNationSlot] = policyValue;
      if (policyValue == 300) {
        this->NotifyActionSlot94(-1, 0);
      }
    }
  }
}

void TriggerNationWarTransitionHandlersIfNeeded(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

void TCountry::ApplyNationStateCode200AndQueueEvent1B(int targetNationSlot) {
  this->ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
  g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1b, this->nationSlot,
                                                                      targetNationSlot, 0);
}

void OrphanCallChain_C2_I28_004e59d0(void) {}
