#include "game/nation_domain_types.h"
#include <stdlib.h>
#include "game/core/stream_byteswap.h"

#include "game/city_ui/TCountry.h"

#include "game/map/TMapMgr.h"
#include "game/core/CString.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/TList.h"
#include "game/nation/TGreatPower.h"
#include "game/globals/nation_globals.h"

#include "game/military/TArmyMgr.h"
#include "game/ui_core/TLanguageMgr.h" // StripCodeStr (display-name load)
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
#include "game/map/TZone.h"
#include "game/nation_stream_serialization.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/military/mapped_flavor_text.h"

#include "game/military_ui/TDiplomacyMgr.h"

#include <new>

static const unsigned int kAddrClassDescTCountry = 0x00653670;

static bool IsRecruitQuarterTickGate(short tickRaw) {
  int tick = static_cast<int>(tickRaw);
  if (((tick / 4) & 1) == 0) {
    return false;
  }
  return tick % 4 == 2;
}

// FUNCTION: IMPERIALISM 0x004d6730
bool TCountry::IsClient(void) const {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d6750
bool TCountry::IsHost(void) const {
  return false;
}

// slot 0x28 — IsRemote (real body).
// FUNCTION: IMPERIALISM 0x004d6770
bool TCountry::IsRemote(void) const {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d6790
void TCountry::PlopDownCity(short selectedRegion, const char* mapCellLabel) {}

IMPLEMENT_DYNCREATE(TCountry, TObject)

// FUNCTION: IMPERIALISM 0x004d67d0
TCountry::TCountry() {}

// FUNCTION: IMPERIALISM 0x004d68f0
void TCountry::InitializeNationStateIdentityAndOwnedRegionList(NationSlot nationSlot) {
  this->nationSlot = nationSlot;
  this->homeTileIndex = -1;
  this->overlayAnchorTileCache = -1;
  this->encodedNationSlot = -1;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    this->needLevelByNation[nationIndex] = 100;
  }

  this->identitySharedString0 = CString(g_pszDescriptorDefaultName);
  bool nameIsDefault = _mbscmp(reinterpret_cast<const unsigned char*>(g_pszDescriptorDefaultName),
                               reinterpret_cast<const unsigned char*>(
                                   static_cast<LPCSTR>(this->identitySharedString0))) == 0;
  if (nameIsDefault) {
    CString flavorName;
    SetSharedStringFromMappedFlavorTextWithLengthClamp(&flavorName, this->nationSlot);
    this->identitySharedString0 = CString(flavorName);
    if (g_pSimMgr != 0) {
      g_pSimMgr->sharedTextSlots[this->nationSlot] = flavorName;
    }
  }
  this->identitySharedString1 = this->identitySharedString0;
  this->treasuryValue = 5000;

  this->militaryUnitList = new TList();

  for (int unitType = 0; unitType < 0x1e; ++unitType) {
    this->unitNameOrdinalByType[unitType] = 1;
  }
  this->unitNameCounter = 1;

  TLongintList* ownedRegions = new TLongintList();
  for (int cityIndex = 0; cityIndex < kProvinceCount; ++cityIndex) {
    if (static_cast<short>(g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode) ==
        nationSlot) {
      ownedRegions->InsertLast(cityIndex);
    }
  }
  this->ownedRegionList = ownedRegions;
}

// FUNCTION: IMPERIALISM 0x004d6ba0
void TCountry::Free(void) {
  if (this->militaryUnitList != 0) {
    this->militaryUnitList->FreePayloadsAndDestroy();
  }
  this->militaryUnitList = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Free();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d6bf0
void TCountry::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadSharedString(&this->identitySharedString0, 0xff);
  g_pSimMgr->sharedTextSlots[this->nationSlot] = this->identitySharedString0;
  stream->ReadSharedString(&this->identitySharedString1, 0xff);

  stream->ReadBytes(&this->nationSlot, 2);
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(this->unitNameOrdinalByType, 0x3c);
  SwapShortArrayBytes(this->unitNameOrdinalByType, 0x1e);

  stream->ReadBytes(&this->unitNameCounter, 2);
  stream->ReadBytes(&this->treasuryValue, 4);
  stream->ReadBytes(&this->homeTileIndex, 4);
  stream->ReadBytes(&this->overlayAnchorTileCache, 4);
  stream->ReadBytes(this->needLevelByNation, 0x2e);
  SwapShortArrayBytes(this->needLevelByNation, 0x17);

  if (this->militaryUnitList->GetCount() != 0) {
    this->militaryUnitList->FreePayloads();
  }
  this->militaryUnitList->ReadFrom(stream);

  int entryCount;
  stream->ReadBytes(&entryCount, 4);
  for (int recruitIndex = 1; recruitIndex <= entryCount; ++recruitIndex) {
    TMilitaryUnit* militaryOrder = new TMilitaryUnit();
    militaryOrder->IMilitaryUnit(0, -1, this->nationSlot, 0);
    militaryOrder->ReadFrom(stream);
  }

  if (this->ownedRegionList->GetSize() != 0) {
    this->ownedRegionList->RemoveAll();
  }
  this->ownedRegionList->NoOpReadFrom(stream);
  stream->ReadBytes(&entryCount, 4);
  for (int regionIndex = 1; regionIndex <= entryCount; ++regionIndex) {
    int entryValue;
    stream->ReadBytes(&entryValue, 4);
    this->ownedRegionList->InsertLast(entryValue);
  }
}

// Serializes the TCountry base sub-object: the identity strings (stream slot 0xac), the
// nation-slot metrics, the per-unit-type name ordinals, the military unit list and the
// owned-region list. The leading TObject::WriteTo is the no-op base-of-base (0x00485f70).

// FUNCTION: IMPERIALISM 0x004d6e60
void TCountry::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);

  stream->WriteSharedString(&this->identitySharedString0);
  stream->WriteSharedString(&this->identitySharedString1);

  stream->WriteBytes(&this->nationSlot, 2);
  stream->WriteBytes(&this->encodedNationSlot, 2);
  WriteShortArrayElems(stream, this->unitNameOrdinalByType, 0x1e);
  stream->WriteBytes(&this->unitNameCounter, 2);
  stream->WriteBytes(&this->treasuryValue, 4);
  stream->WriteBytes(&this->homeTileIndex, 4);
  stream->WriteBytes(&this->overlayAnchorTileCache, 4);
  WriteShortArrayElemsRev(stream, this->needLevelByNation, 0x17);

  WriteTrackedListToStream(stream, this->militaryUnitList);
  WriteIntListToStream(stream, this->ownedRegionList);
}

// FUNCTION: IMPERIALISM 0x004d7070
void TCountry::MultiReadFrom(TStream* stream, int unusedArg) {
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(&this->treasuryValue, 4);
  stream->ReadBytes(&this->homeTileIndex, 4);
  stream->ReadBytes(&this->overlayAnchorTileCache, 4);
}

// FUNCTION: IMPERIALISM 0x004d70e0
void TCountry::MultiWriteTo(TStream* stream) {
  stream->WriteBytes(&this->encodedNationSlot, 2);
  stream->WriteBytes(&this->treasuryValue, 4);
  stream->WriteBytes(&this->homeTileIndex, 4);
  stream->WriteBytes(&this->overlayAnchorTileCache, 4);
}

// FUNCTION: IMPERIALISM 0x004d7150
void TCountry::SetCenterTile(int value) {
  this->overlayAnchorTileCache = static_cast<short>(value);
}

// FUNCTION: IMPERIALISM 0x004d7170
short TCountry::GeopoliticalCenter() {
  if (overlayAnchorTileCache == -1) {
    overlayAnchorTileCache = static_cast<short>(
        g_pGlobalMapState->ComputeRepresentativeTileIndexForNationWithWrapBias(nationSlot, true));
  }
  return static_cast<short>(overlayAnchorTileCache);
}

// FUNCTION: IMPERIALISM 0x004d71b0
void TCountry::InitialMilitia(void) {
  TSimMgr* simMgr = g_pSimMgr;
  if (simMgr->scenarioMapIndexPlusOne > 0) {
    g_pGlobalMapState->BuildFort(
        g_pGlobalMapState->terrainStateTable[static_cast<short>(this->homeTileIndex)]
            .cityRecordIndex);
    return;
  }
  int ordinal = 1;
  if (this->ownedRegionList->GetSize() >= 1) {
    do {
      int regionId = this->ownedRegionList->At(ordinal);
      short regionTerrainId = g_pGlobalMapState->cityScoreTable[regionId].cityTileIndex;
      if ((g_pGlobalMapState->terrainStateTable[regionTerrainId].activeFlags & 1) != 0) {
        TMilitaryUnit* order = new TMilitaryUnit();
        order->IMilitaryUnit(2, regionId, this->nationSlot);
        if (g_pSimMgr->difficultyLevel < kDifficultyNormal) {
          order->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        order = new TMilitaryUnit();
        order->IMilitaryUnit(2, regionId, this->nationSlot);
        if (g_pSimMgr->difficultyLevel < kDifficultyNormal) {
          order->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        order = new TMilitaryUnit();
        order->IMilitaryUnit(7, regionId, this->nationSlot);
        if (g_pSimMgr->difficultyLevel < kDifficultyNormal) {
          order->SetOrders(static_cast<UnitOrder>(2), -1);
        }
        g_pGlobalMapState->BuildFort(regionId);
        if (this->nationSlot < 7 && g_apNationStates[this->nationSlot]->diplomacyEligibility == 0 &&
            g_pSimMgr->difficultyLevel == kDifficultyNighOnImpossible) {
          order = new TMilitaryUnit();
          order->IMilitaryUnit(6, regionId, this->nationSlot);
          if (g_pSimMgr->difficultyLevel < kDifficultyNormal) {
            order->SetOrders(static_cast<UnitOrder>(2), -1);
          }
          order = new TMilitaryUnit();
          order->IMilitaryUnit(5, regionId, this->nationSlot);
          if (g_pSimMgr->difficultyLevel < kDifficultyNormal) {
            order->SetOrders(static_cast<UnitOrder>(2), -1);
          }
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          TCity* cityForPort = (nation != 0) ? nation->city : 0;
          TZone* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(cityForPort);
          CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, portZone, this->nationSlot, 0);
        }
        if (this->nationSlot < kMajorNationCount) {
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          if (nation->diplomacyEligibility != 0 &&
              g_pSimMgr->difficultyLevel == kDifficultyIntroductory) {
            TCity* cityForPort = (nation != 0) ? nation->city : 0;
            TZone* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(cityForPort);
            CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, portZone->primaryNeighbors[0],
                                                           this->nationSlot, 0);
          }
        }
      }
      this->AddMilitia(regionId);
      this->AddMilitia(regionId);
      this->AddMilitia(regionId);
      if (g_pSimMgr->difficultyLevel > kDifficultyNormal) {
        this->AddMilitia(regionId);
        if (this->nationSlot >= kMajorNationCount) {
          TMilitaryUnit* lateOrder = new TMilitaryUnit();
          lateOrder->IMilitaryUnit(7, regionId, this->nationSlot);
        }
      }
      if (*g_pGlobalMapState->scenarioTagText == '+') {
        TMilitaryUnit* bonusOrder = new TMilitaryUnit();
        bonusOrder->IMilitaryUnit(2, regionId, this->nationSlot);
        bonusOrder->SetOrders(static_cast<UnitOrder>(2), -1);
      }
      ++ordinal;
    } while (ordinal <= this->ownedRegionList->GetSize());
  }
  this->NameUnits();
}

// FUNCTION: IMPERIALISM 0x004d7770
void TCountry::AddMilitia(int nodeContext) {
  int capabilityBonus = 0;
  if (static_cast<unsigned short>(this->nationSlot) < kMajorNationCount) {
    const TTechMgr::MilitaryCapRow& capabilityRow = g_pTechMgr->abilityActiveRows[this->nationSlot];
    if (capabilityRow.abilityActiveById[0x10] != 0) {
      capabilityBonus = 0x10;
    } else {
      char capabilityFlag = static_cast<char>(capabilityRow.abilityActiveById[8]);
      capabilityBonus = capabilityFlag > 0 ? 8 : 0;
    }
  }
  TMilitaryUnit* militaryOrder = new TMilitaryUnit();
  militaryOrder->IMilitaryUnit(static_cast<short>(capabilityBonus), nodeContext, this->nationSlot);
  militaryOrder->SetOrders(static_cast<UnitOrder>(2), -1);
}

// FUNCTION: IMPERIALISM 0x004d7860
void TCountry::FormatOverlayTerrainLabelText(CString* out) {
  if (this == 0) {
    CString defaultName(g_pszDescriptorDefaultName);
    *out = defaultName;
  } else {
    *out = g_pSimMgr->GetCountryName(nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004d7930
void TCountry::AssignSharedStringFromDescriptorNameOrDefault(CString* out) {
  if (this == 0) {
    CString defaultName(g_pszDescriptorDefaultName);
    *out = defaultName;
  } else {
    *out = g_pSimMgr->GetCountryNameWithCode(this->nationSlot);
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
void TCountry::GetName(CString* destString) {
  *destString = g_pLanguageMgr->StripCodeStr(identitySharedString1);
}

// FUNCTION: IMPERIALISM 0x004d7ac0
void TCountry::GetNameWithCode(CString* destString) {
  *destString = identitySharedString1;
}

// FUNCTION: IMPERIALISM 0x004d7ae0
void TCountry::AddToTreasury(int amount) {
  this->treasuryValue += amount;
}

// FUNCTION: IMPERIALISM 0x004d7b00
bool TCountry::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                 ResourceKindStorage resourceKind) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7b20
void TCountry::ChangeMaster(int targetNationSlot, int mode) {
  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
    g_pGameFlowState->SendChangeMaster(this->nationSlot, targetNationSlot, mode);
  }

  if (mode == 1) {
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, targetNationSlot, kDiplomacyRelationshipJoinedEmpire);
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        targetNationSlot, this->nationSlot, kDiplomacyRelationshipJoinedEmpire);
  }

  if (this->nationSlot < kMajorNationCount) {
    g_pSimMgr->ReduceNumGPs();
  }

  if (mode == 0) {
    this->BecomeProtectorateOf(targetNationSlot);
    return;
  }
  if (mode == 1) {
    this->BecomeColonyOf(targetNationSlot);
    return;
  }
  this->RegainIndependence();
}

// FUNCTION: IMPERIALISM 0x004d7c00
void TCountry::BecomeProtectorateOf(int targetNationSlot) {
  this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot)) &&
        nationSlot != this->nationSlot && nationSlot != targetNationSlot) {
      TCountry* terrain = g_apTerrainTypeDescriptorTable[nationSlot];
      terrain->NewStatusFor(this->nationSlot, 100);
    }
  }
  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7c90
void TCountry::BecomeColonyOf(int targetNationSlot) {
  this->encodedNationSlot = static_cast<short>(targetNationSlot + 200);
  this->SetTradePolicyTo(static_cast<NationSlot>(targetNationSlot), 100);

  int nationSlot = 0;
  do {
    if (g_pSimMgr->ReallyInTheGame(nationSlot) && nationSlot != this->nationSlot &&
        nationSlot != targetNationSlot) {
      TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
      terrainDescriptor->NewStatusFor(this->nationSlot, 200);
    }
    ++nationSlot;
  } while (nationSlot < kNationSlotCount);

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7d20
bool TCountry::IsColonyOf(int nationCode) {
  int adjusted = static_cast<short>(this->encodedNationSlot) - 0xc8;
  return adjusted == nationCode;
}

// FUNCTION: IMPERIALISM 0x004d7d50
void TCountry::RegainIndependence(void) {
  this->identitySharedString0 = this->identitySharedString1;
}

// FUNCTION: IMPERIALISM 0x004d7d70
void TCountry::LoseProvince(int regionId) {
  this->ownedRegionList->Delete(regionId);
}

// FUNCTION: IMPERIALISM 0x004d7da0
void TCountry::AddProvince(int regionId) {
  this->ownedRegionList->InsertLast(regionId);
}

// FUNCTION: IMPERIALISM 0x004d7dd0
void TCountry::NewStatusFor(int targetNationSlot, int policyCode) {
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
void TCountry::DeliverItem(short amount) {}

// Mac oracle: TCountry::GenerateEthnicName(CStr32&) const.
// FUNCTION: IMPERIALISM 0x004d7eb0
void TCountry::GenerateEthnicName(CString* out) const {
  GenerateMappedFlavorTextByTableSlot(out, nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7ee0
short TCountry::GetAmtUnsold(short resourceKind) {
  return 0;
}

// slot 0x1d — GetMerchantCapacity (real body).
// FUNCTION: IMPERIALISM 0x004d7f00
short TCountry::GetMerchantCapacity(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f20
short TCountry::GetStockpile(short resourceKind) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f40
short TCountry::GetTradeOffersFor(short resourceKind) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f60
bool TCountry::IsInConsortiumWith(short policyCode) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7f80
void TCountry::AddNoticeFrom(short sourceNation, short actionCode) {}

// FUNCTION: IMPERIALISM 0x004d7fa0
void TCountry::PurchaseItem(short resourceKind, short amount, short price) {}

// FUNCTION: IMPERIALISM 0x004d7fc0
bool TCountry::StillBuyingItem(ResourceKindStorage resourceKind) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7fe0
void TCountry::AddOfferFrom(NationSlot sourceNationSlot,
                            DiplomacyProposalCodeStorage proposalCode) {}

// FUNCTION: IMPERIALISM 0x004d8000
void TCountry::NameUnits(void) {
  int ordinal = 1;
  if (this->militaryUnitList->GetCount() < 1) {
    return;
  }
  do {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(this->militaryUnitList->GetEntryByOrdinal(ordinal));
    if (unit->unitRosterId == 0) {
      if (unit->orderType < EncodeMilitaryUnitKind(kMilitaryUnitGeneralEra1)) {
        CString ordinalText;
        CString typeName;
        CString composedName;
        short unitType = unit->orderType;
        TSimMgr* simMgr = g_pSimMgr;
        short* nameOrdinalCounter = &this->unitNameOrdinalByType[unitType];
        simMgr->NumToOrdinal(*nameOrdinalCounter, &ordinalText);
        simMgr->GetString(0x2717, unitType, &typeName);
        CString withSeparator = ordinalText + CString(" ");
        CString fullName = withSeparator + typeName;
        composedName = fullName;
        unit->name = composedName;
        unit->unitRosterId = this->unitNameCounter;
        ++this->unitNameCounter;
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
        unit->name = flavorName;
        unit->unitRosterId = this->unitNameCounter;
        ++this->unitNameCounter;
      }
    }
    ++ordinal;
    ordinal = static_cast<short>(ordinal);
  } while (ordinal <= this->militaryUnitList->GetCount());
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
  CIterator unitIter(this->militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    powerSum += g_aUnitOrderCostProfileByAbilityId[unit->orderType][2];
  }
  return powerSum;
}

// FUNCTION: IMPERIALISM 0x004d87b0
int TCountry::GetCapitolProvince(void) {
  return g_pGlobalMapState->terrainStateTable[static_cast<short>(this->homeTileIndex)]
      .cityRecordIndex;
}

// FUNCTION: IMPERIALISM 0x004d87e0
void TCountry::GrowMilitia(void) {
  short tickRaw = g_pSimMgr->economicTurn;
  if (!IsRecruitQuarterTickGate(tickRaw)) {
    return;
  }

  int garrisonThreshold = 3;
  if (static_cast<unsigned short>(this->nationSlot) < kMajorNationCount) {
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
      unitChain = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain;
    }
    for (; unitChain != 0; unitChain = static_cast<TMilitaryUnit*>(unitChain->nextAtLocation)) {
      if (unitChain->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
        garrisonCount = static_cast<short>(garrisonCount + 1);
      }
    }
    if (garrisonCount < static_cast<short>(garrisonThreshold)) {
      this->AddMilitia(static_cast<int>(regionId));
    }
    ++ordinal;
    regionCount = this->ownedRegionList->GetSize();
  } while (ordinal <= regionCount);
}

// FUNCTION: IMPERIALISM 0x004d8920
void TCountry::SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) {
  if (nationSlot != this->nationSlot) {
    this->needLevelByNation[nationSlot] = tradePolicy;
  }
}

// FUNCTION: IMPERIALISM 0x0057f0e0
bool TCountry::IsNationProfileInMinorRange100To199() {
  if (this != NULL) {
    if (encodedNationSlot >= 100 && encodedNationSlot < 200) {
      return true;
    }
  }
  return false;
}
