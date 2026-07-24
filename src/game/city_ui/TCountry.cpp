#include <stdlib.h>

#include "game/city_ui/TCountry.h"

#include "game/map/TMapMgr.h"
#include "game/ui_screens/CString.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"

#include "game/military/TArmyMgr.h"
#include "game/ui_core/TLanguageMgr.h" // NormalizeRuntimeCredentialNameToken (display-name load)
#include "game/ui_screens/TNewsMgr.h"
#include "game/city/TCity.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_core/CIterator.h"
#include "game/military/TMilitaryUnit.h"
#include "game/core/TStream.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/military/TUnit.h"
#include "game/ui_screens/TZone.h"
#include "game/nation_stream_serialization.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/military/mapped_flavor_text.h"

#include "game/military_ui/TDiplomacyMgr.h"

#include <new>

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

// SYNTHETIC: IMPERIALISM 0x004d66a0
// TCountry::CreateObject

// FUNCTION: IMPERIALISM 0x004d6730
bool TCountry::IsClient(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d6750
bool TCountry::IsHost(void) {
  return false;
}

// slot 0x28 — IsRemote (real body).
// FUNCTION: IMPERIALISM 0x004d6770
bool TCountry::IsRemote(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d6790
void TCountry::SetNationSelectedRegionAndMapCellLabel(short selectedRegion, char* mapCellLabel) {
  (void)selectedRegion;
  (void)mapCellLabel;
}

// SYNTHETIC: IMPERIALISM 0x004d67b0
// TCountry::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCountry, TObject)

// FUNCTION: IMPERIALISM 0x004d67d0
TCountry::TCountry() {}

// SYNTHETIC: IMPERIALISM 0x004d6850
// TCountry::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004d68f0
void TCountry::InitializeNationStateIdentityAndOwnedRegionList(NationSlot nationSlot) {
  this->nationSlot = nationSlot;
  this->homeTileIndex = -1;
  this->overlayAnchorTileCache8c = -1;
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
  if (g_pSimMgr != 0) {
    g_pSimMgr->sharedTextSlots[nationSlot] = this->identitySharedString0;
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

  TLongintList* ownedRegions = new TLongintList();
  for (int cityIndex = 0; cityIndex < 0x180; ++cityIndex) {
    if (static_cast<short>(g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00) ==
        nationSlot) {
      ownedRegions->InsertLast(cityIndex);
    }
  }
  this->ownedRegionList = ownedRegions;
}

// FUNCTION: IMPERIALISM 0x004d6ba0
void TCountry::Free(void) {
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

// FUNCTION: IMPERIALISM 0x004d6bf0
void TCountry::ReadFrom(TStream* stream) {
  int streamState = reinterpret_cast<int>(stream);
  stream->streamSlot70(&this->identitySharedString0, 0xff);
  stream->streamSlot70(&this->identitySharedString1, 0xff);

  this->identitySharedString1 = g_pSimMgr->sharedTextSlots[this->nationSlot];
  stream->ReadBytes(&this->identitySharedString0, 4);

  stream->ReadBytes(&this->nationSlot, 2);
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(this->unitNameOrdinalByType, 0x3c);
  SwapAdjacentBytesInShortArray(this->unitNameOrdinalByType, 0x1e);

  stream->ReadBytes(&this->unitNameCounter84, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->homeTileIndex, 4);
  stream->ReadBytes(&this->overlayAnchorTileCache8c, 4);
  stream->ReadBytes(this->needLevelByNation, 0x2e);
  SwapAdjacentBytesInShortArray(this->needLevelByNation, 0x17);

  if (this->militaryUnitList44->GetCount() != 0) {
    this->militaryUnitList44->FreePayloads();
  }
  this->militaryUnitList44->ReadFrom(reinterpret_cast<TStream*>(streamState));

  int recruitCount = 0;
  stream->ReadBytes(&recruitCount, 4);
  int recruitIndex = 1;
  if (recruitCount > 0) {
    do {
      TMilitaryUnit* militaryOrder = new TMilitaryUnit();
      if (militaryOrder != nullptr) {
        militaryOrder->IMilitaryUnit(0, 0, this->nationSlot);
        militaryOrder->ReadFrom(stream);
      }
      recruitIndex = recruitIndex + 1;
    } while (recruitIndex <= recruitCount);
  }

  if (this->ownedRegionList->GetSize() != 0) {
    this->ownedRegionList->RemoveAll();
  }
  this->ownedRegionList->NoOpReadFrom(stream);
  int regionDeserializeCount = 0;
  stream->ReadBytes(&regionDeserializeCount, 4);
  int regionIndex = 1;
  if (regionDeserializeCount > 0) {
    do {
      int entryValue = 0;
      stream->ReadBytes(&entryValue, 4);
      this->ownedRegionList->InsertLast(entryValue);
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
  stream->WriteBytesSlot78(&this->homeTileIndex, 4);
  stream->WriteBytesSlot78(&this->overlayAnchorTileCache8c, 4);
  WriteShortArrayElems(stream, this->needLevelByNation, 0x17);

  WriteTrackedListToStream(stream, this->militaryUnitList44);
  WriteIntListToStream(stream, this->ownedRegionList);
}

// FUNCTION: IMPERIALISM 0x004d7070
void TCountry::ReadCoreFieldsFromStream(TStream* stream, int unusedArg) {
  (void)unusedArg;
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->homeTileIndex, 4);
  stream->ReadBytes(&this->overlayAnchorTileCache8c, 4);
}

// FUNCTION: IMPERIALISM 0x004d70e0
void TCountry::WriteCoreFieldsToStream(TStream* stream) {
  stream->WriteBytesSlot78(&this->encodedNationSlot, 2);
  stream->WriteBytesSlot78(&this->treasuryValue10, 4);
  stream->WriteBytesSlot78(&this->homeTileIndex, 4);
  stream->WriteBytesSlot78(&this->overlayAnchorTileCache8c, 4);
}

// FUNCTION: IMPERIALISM 0x004d7150
void TCountry::SetSerializedField8c(short value) {
  this->overlayAnchorTileCache8c = value;
}

// FUNCTION: IMPERIALISM 0x004d7170
short TCountry::GetOrComputeOverlayAnchorTileIndex() {
  if (overlayAnchorTileCache8c == -1) {
    overlayAnchorTileCache8c =
        g_pGlobalMapState->ComputeRepresentativeTileIndexForNationWithWrapBias(nationSlot, 1);
  }
  return static_cast<short>(overlayAnchorTileCache8c);
}

// FUNCTION: IMPERIALISM 0x004d71b0
void TCountry::SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void) {
  TSimMgr* localization = g_pSimMgr;
  if (localization->scenarioMapIndexPlusOne > 0) {
    g_pGlobalMapState->SetProvinceCapitalTileFlagBit08(
        g_pGlobalMapState->terrainStateTable[static_cast<short>(this->homeTileIndex)]
            .cityRecordIndex);
    return;
  }
  int ordinal = 1;
  if (this->ownedRegionList->GetSize() >= 1) {
    do {
      int regionId = this->ownedRegionList->At(ordinal);
      short regionTerrainId = g_pGlobalMapState->cityScoreTable[regionId].cityTileIndex04;
      if ((g_pGlobalMapState->terrainStateTable[regionTerrainId].activeFlags1c & 1) != 0) {
        TMilitaryUnit* order = new TMilitaryUnit();
        order->IMilitaryUnit(2, regionId, this->nationSlot);
        if (g_pSimMgr->difficultyLevel < 2) {
          order->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        order = new TMilitaryUnit();
        order->IMilitaryUnit(2, regionId, this->nationSlot);
        if (g_pSimMgr->difficultyLevel < 2) {
          order->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        order = new TMilitaryUnit();
        order->IMilitaryUnit(7, regionId, this->nationSlot);
        if (g_pSimMgr->difficultyLevel < 2) {
          order->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        g_pGlobalMapState->SetProvinceCapitalTileFlagBit08(regionId);
        if (this->nationSlot < 7 &&
            g_apNationStates[this->nationSlot]->diplomacyEligibilityA0 == 0 &&
            g_pSimMgr->difficultyLevel == 4) {
          order = new TMilitaryUnit();
          order->IMilitaryUnit(6, regionId, this->nationSlot);
          if (g_pSimMgr->difficultyLevel < 2) {
            order->SetOrders(static_cast<UnitOrder>(2), -1);
          }
          order = new TMilitaryUnit();
          order->IMilitaryUnit(5, regionId, this->nationSlot);
          if (g_pSimMgr->difficultyLevel < 2) {
            order->SetOrders(static_cast<UnitOrder>(2), -1);
          }
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          TCity* cityForPort = (nation != 0) ? nation->city : 0;
          TZone* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(cityForPort);
          CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, portZone, this->nationSlot, 0);
        }
        if (this->nationSlot < 7) {
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          if (nation->diplomacyEligibilityA0 != 0 && g_pSimMgr->difficultyLevel == 0) {
            TCity* cityForPort = (nation != 0) ? nation->city : 0;
            TZone* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(cityForPort);
            CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, portZone->primaryNeighbors[0],
                                                           this->nationSlot, 0);
          }
        }
      }
      this->CreateMilitaryRecruitOrderForNode(regionId);
      this->CreateMilitaryRecruitOrderForNode(regionId);
      this->CreateMilitaryRecruitOrderForNode(regionId);
      if (g_pSimMgr->difficultyLevel > 2) {
        this->CreateMilitaryRecruitOrderForNode(regionId);
        if (this->nationSlot >= 7) {
          TMilitaryUnit* lateOrder = new TMilitaryUnit();
          lateOrder->IMilitaryUnit(7, regionId, this->nationSlot);
        }
      }
      if (*g_pGlobalMapState->scenarioTagText1c == '+') {
        TMilitaryUnit* bonusOrder = new TMilitaryUnit();
        bonusOrder->IMilitaryUnit(2, regionId, this->nationSlot);
        bonusOrder->SetOrders(static_cast<UnitOrder>(2), -1);
      }
      ++ordinal;
    } while (ordinal <= this->ownedRegionList->GetSize());
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}

// FUNCTION: IMPERIALISM 0x004d7770
void TCountry::CreateMilitaryRecruitOrderForNode(int nodeContext) {
  int capabilityBonus = 0;
  if (static_cast<unsigned short>(this->nationSlot) < 7) {
    const TTechMgr::MilitaryCapRow& capabilityRow =
        g_pCityOrderCapabilityState->abilityActiveRows395[this->nationSlot];
    if (capabilityRow.abilityActiveById[0x10] != 0) {
      capabilityBonus = 0x10;
    } else {
      char capabilityFlag = static_cast<char>(capabilityRow.abilityActiveById[8]);
      capabilityBonus = (static_cast<int>(-capabilityFlag) >> 0x1f) & 8;
    }
  }
  TMilitaryUnit* militaryOrder = new TMilitaryUnit();
  militaryOrder->IMilitaryUnit(static_cast<short>(capabilityBonus), nodeContext, this->nationSlot);
  militaryOrder->SetOrders(static_cast<UnitOrder>(2), -1);
}

// FUNCTION: IMPERIALISM 0x004d7860
void TCountry::FormatOverlayTerrainLabelText(CString* out) {
  if (this == 0) {
    CString defaultName(g_pszDescriptorDefaultName_00653300);
    *out = defaultName;
  } else {
    *out = g_pSimMgr->LoadNormalizedCredentialName(nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004d7930
void TCountry::AssignSharedStringFromDescriptorNameOrDefault(CString* out) {
  if (this == 0) {
    CString defaultName(g_pszDescriptorDefaultName_00653300);
    *out = defaultName;
  } else {
    *out = g_pSimMgr->AssignSharedStringFromIndexedSlot7C(this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004d7a00
void TCountry::SetNationDisplayNameAndLocalizationSlotRef(const CString& name) {
  this->identitySharedString0 = name;
  if (g_pSimMgr != 0) {
    g_pSimMgr->sharedTextSlots[this->nationSlot] = name;
  }
}

// FUNCTION: IMPERIALISM 0x004d7a40
void TCountry::LoadNationDisplayNameSharedRefFromField8(CString* destString) {
  *destString = g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&identitySharedString1);
}

// FUNCTION: IMPERIALISM 0x004d7ae0
void TCountry::AddToTreasury(int amount) {
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
  if (g_pSimMgr != 0 && g_pSimMgr->difficultyLevel == 1) {
    g_pGameFlowState->DispatchJoinEmpireModeEventPacket24_27(this->nationSlot, targetNationSlot,
                                                             mode);
  }

  if (mode == 1) {
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, targetNationSlot, kDiplomacyRelationshipJoinedEmpire);
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        targetNationSlot, this->nationSlot, kDiplomacyRelationshipJoinedEmpire);
  }

  if (this->nationSlot < 7) {
    g_pSimMgr->ReduceNumGPs();
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
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0 &&
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
  this->SetTradePolicyTo(static_cast<NationSlot>(targetNationSlot), 100);

  int nationSlot = 0;
  do {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
        nationSlot != this->nationSlot && nationSlot != targetNationSlot) {
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
  int adjusted = static_cast<short>(this->encodedNationSlot) - 0xc8;
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
  this->ownedRegionList->Delete(regionId);
}

// FUNCTION: IMPERIALISM 0x004d7da0
void TCountry::AddRegionIdToNationOwnedRegionList(int regionId) {
  this->ownedRegionList->InsertLast(regionId);
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

// Mac oracle: TCountry::GenerateEthnicName(CStr32&) const.
// FUNCTION: IMPERIALISM 0x004d7eb0
void TCountry::GenerateEthnicName(CString* out) const {
  GenerateMappedFlavorTextByTableSlot(out, nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7ee0
short TCountry::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
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
char TCountry::ReturnFalseNationStateCapabilityFlag90(short arg) {
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
void TCountry::QueueDiplomacyProposalCodeForTargetNation(DiplomacyProposalCodeStorage proposalCode,
                                                         NationSlot targetNationSlot) {
  (void)proposalCode;
  (void)targetNationSlot;
}

// FUNCTION: IMPERIALISM 0x004d8000
void TCountry::AssignDisplayNamesToUnnamedMilitaryUnits(void) {
  int ordinal = 1;
  if (this->militaryUnitList44->GetCount() < 1) {
    return;
  }
  do {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(this->militaryUnitList44->GetEntryByOrdinal(ordinal));
    if (unit->field_1A == 0) {
      if (unit->orderType < EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1)) {
        CString ordinalText;
        CString typeName;
        CString composedName;
        short unitType = unit->orderType;
        TSimMgr* localization = g_pSimMgr;
        short* nameOrdinalCounter = &this->unitNameOrdinalByType[unitType];
        localization->NumToOrdinal(*nameOrdinalCounter, &ordinalText);
        localization->GetString(0x2717, unitType, &typeName);
        CString withSeparator = ordinalText + CString(" ");
        CString fullName = withSeparator + typeName;
        composedName = fullName;
        unit->name24 = composedName;
        unit->field_1A = this->unitNameCounter84;
        ++this->unitNameCounter84;
        ++*nameOrdinalCounter;
      } else {
        CString flavorBase;
        CString flavorName;
        g_pSimMgr->GetString(0x2744, 0, &flavorBase);
        do {
          GenerateMappedFlavorTextByTableSlot(&flavorName, this->nationSlot);
        } while (flavorName.GetLength() > 0xf - flavorBase.GetLength());
        CString withSeparator = flavorBase + CString(" ");
        CString fullName = withSeparator + flavorName;
        flavorName = fullName;
        unit->name24 = flavorName;
        unit->field_1A = this->unitNameCounter84;
        ++this->unitNameCounter84;
      }
    }
    ++ordinal;
    ordinal = static_cast<short>(ordinal);
  } while (ordinal <= this->militaryUnitList44->GetCount());
}

int DecodeTerrainNationSlotFromDescriptor(const TCountry* terrain,
                                          EncodedNationSlot encodedNationSlot) {
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
int TCountry::ComputeWeightedNeighborLinkScoreForNode(int nodeIndex) {
  return g_pMapContextActionManager->ComputeWeightedNeighborLinkScoreForNodeIndex(nodeIndex);
}

// FUNCTION: IMPERIALISM 0x004d83c0
int TCountry::SumWeightedNeighborLinkScoreForLinkedNodes(void) {
  int sum = 0;
  int index = 1;
  while (index <= ownedRegionList->GetSize()) {
    sum += g_pMapContextActionManager->ComputeWeightedNeighborLinkScoreForNodeIndex(
        ownedRegionList->At(index));
    ++index;
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004d8430
int TCountry::ComputeSelectedMilitaryPowerScore() {
  int powerSum = 0;
  CIterator unitIter(this->militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    powerSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  return powerSum;
}

// FUNCTION: IMPERIALISM 0x004d87b0
int TCountry::GetHomeRegionCityRecordIndex(void) {
  return g_pGlobalMapState->terrainStateTable[static_cast<short>(this->homeTileIndex)]
      .cityRecordIndex;
}

// FUNCTION: IMPERIALISM 0x004d87e0
void TCountry::QueueRecruitOrdersForUndergarrisonedRegions(void) {
  short tickRaw = g_pSimMgr->economicTurn;
  if (!IsRecruitQuarterTickGate(tickRaw)) {
    return;
  }

  int garrisonThreshold = 3;
  if (static_cast<unsigned short>(this->nationSlot) < 7) {
    garrisonThreshold = 4;
  }

  int regionCount = this->ownedRegionList->GetSize();
  int ordinal = 1;
  if (ordinal > regionCount) {
    return;
  }
  do {
    short regionId = static_cast<short>(this->ownedRegionList->At(ordinal));
    short garrisonCount = 0;
    TMilitaryUnit* unitChain;
    if ((regionId < 0) || (0x17f < regionId)) {
      unitChain = 0;
    } else {
      unitChain = *reinterpret_cast<TMilitaryUnit**>(
          reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + 0x98 +
          static_cast<int>(regionId) * 0xa8);
    }
    for (; unitChain != 0; unitChain = static_cast<TMilitaryUnit*>(unitChain->nextOnTile)) {
      if (unitChain->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
        garrisonCount = static_cast<short>(garrisonCount + 1);
      }
    }
    if (garrisonCount < static_cast<short>(garrisonThreshold)) {
      this->CreateMilitaryRecruitOrderForNode(static_cast<int>(regionId));
    }
    ordinal = ordinal + 1;
    regionCount = this->ownedRegionList->GetSize();
  } while (ordinal <= regionCount);
}

// FUNCTION: IMPERIALISM 0x004d8920
void TCountry::SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) {
  if (nationSlot != this->nationSlot) {
    this->needLevelByNation[nationSlot] = tradePolicy;
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

void TCountry::SetNationTradePolicyValueForTargetAndNotify(NationSlot targetNationSlot,
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

void TCountry::ApplyNationStateCode200AndQueueEvent1B(int targetNationSlot) {
  this->ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
  g_pNewsMgr->AddTreatyEvent(kInterNationEventNationJoinedEmpire, this->nationSlot,
                             targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x0057f0e0
bool TCountry::IsNationProfileInMinorRange100To199() {
  if (this != nullptr) {
    if (encodedNationSlot >= 100 && encodedNationSlot < 200) {
      return true;
    }
  }
  return false;
}
