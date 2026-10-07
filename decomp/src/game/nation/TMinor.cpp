#include "game/nation_domain_types.h"
#include "game/map_domain_types.h"
#include "game/nation/TMinor.h"
#include "game/resource_domain_types.h"
#include "game/core/stream_byteswap.h"

#include <stdlib.h>

#include "game/ui_core/CIterator.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/military/TArmyMgr.h"
#include "game/military/TCivUnit.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/map/TMapMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/city_ui/TLongintList.h"
#include "game/core/TStream.h"
#include "game/city/TTown.h"
#include "game/military/TUnit.h"
#include "game/nation_stream_serialization.h"

#include <new>

IMPLEMENT_DYNCREATE(TMinor, TCountry)

// FUNCTION: IMPERIALISM 0x004e3710
TMinor::TMinor() {}

// FUNCTION: IMPERIALISM 0x004e3830
void TMinor::IMinor(NationSlot nationSlot) {
  CString unusedText;
  InitializeNationStateIdentityAndOwnedRegionList(nationSlot);

  primaryManufacturedRequestFulfilledAmount = 0;
  primaryManufacturedRequest = -10;
  secondaryManufacturedRequest = -10;
  secondaryManufacturedRequestFulfilledAmount = 0;
  int i;
  for (i = 0; i < kResourceKindCount; ++i) {
    tradeOffersByResource[i] = 0;
    grantAmountsByResource[i] = 0;
    needCurrentByType[i] = 0;
    independentResourceCountByType[i] = 0;
    foreignControlledResourceYieldByType[i] = 0;
    memset(&foreignControlledResourceYieldByTypeAndMajorNation[i], 0,
           sizeof(TMinorForeignResourceYieldByMajorNation));
  }

  for (int tileIndex = 0; tileIndex < kStrategicTileCount; ++tileIndex) {
    if (g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag == this->nationSlot) {
      for (int edge = 0; edge < 2; ++edge) {
        int resourceType = static_cast<char>(
            g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge]);
        if (g_pGlobalMapState->terrainStateTable[tileIndex].gateFlag != 0xf && resourceType != -1) {
          ++needCurrentByType[resourceType];
          ++independentResourceCountByType[resourceType];
        }
      }
    }
  }

  if (!g_bMultiplayerScenarioSetupActive) {
    bool noImmediateDispatch = !IsRemote();
    if (noImmediateDispatch || g_pSimMgr->scenarioMapIndexPlusOne != 0) {
      TLongintList* candidateTiles = new TLongintList();
      short selectedTile = -1;
      short tile;
      for (tile = 0; tile < kStrategicTileCount; ++tile) {
        if (g_pGlobalMapState->terrainStateTable[tile].ownerNationTag == nationSlot) {
          TTerrainStateRecord* record = &g_pGlobalMapState->terrainStateTable[tile];
          if (record->activeFlags & 1) {
            selectedTile = tile;
          }
          if (g_pGlobalMapState->IsValidSecondaryNationHomeTileCandidate(tile)) {
            candidateTiles->InsertLast(tile);
          }
        }
      }
      if (selectedTile == -1) {
        int candidateCount = candidateTiles->GetSize();
        // LIBRARY: rand (0x005e83f0)
        selectedTile = static_cast<short>(candidateTiles->At(rand() % candidateCount + 1));
      }
      // Constructed and destroyed unused in the original (EH states 1/2).
      CString unusedTextA;
      CString unusedTextB;
      g_pGlobalMapState->ResetTileToBaseTransportFlag(selectedTile);
      homeTileIndex = selectedTile;
      if (candidateTiles != 0) {
        candidateTiles->Free();
      }
      g_pActiveMapOrderContext->EnsurePortZoneForTile(static_cast<short>(homeTileIndex));
    }
  }

  needCurrentByType[7] = 5;
  switch (nationSlot) {
  case 7:
    primaryManufacturedPriceThreshold = 0x44c;
    secondaryManufacturedPriceThreshold = 0x23a;
    generalOfferPriceThreshold = 0xc3;
    randomOfferPriceThreshold = 0x5a;
    coalOfferPriceThreshold = 0x69;
    ironOfferPriceThreshold = 0x8a;
    oilOfferPriceThreshold = 0x90;
    consortiumMembers[0] = 7;
    consortiumMembers[1] = 8;
    consortiumMembers[2] = 9;
    consortiumMembers[3] = 0xa;
    break;
  case 8:
    primaryManufacturedPriceThreshold = 0x47e;
    secondaryManufacturedPriceThreshold = 0x249;
    generalOfferPriceThreshold = 0xaf;
    randomOfferPriceThreshold = 0x52;
    coalOfferPriceThreshold = 0x75;
    ironOfferPriceThreshold = 0x72;
    oilOfferPriceThreshold = 0x84;
    consortiumMembers[0] = 7;
    consortiumMembers[1] = 8;
    consortiumMembers[2] = 9;
    consortiumMembers[3] = 0xa;
    break;
  case 9:
    primaryManufacturedPriceThreshold = 0x4b0;
    secondaryManufacturedPriceThreshold = 0x258;
    generalOfferPriceThreshold = 0x9b;
    randomOfferPriceThreshold = 0x4a;
    coalOfferPriceThreshold = 0x81;
    ironOfferPriceThreshold = 0x7e;
    oilOfferPriceThreshold = 0x78;
    consortiumMembers[0] = 7;
    consortiumMembers[1] = 8;
    consortiumMembers[2] = 9;
    consortiumMembers[3] = 0xa;
    break;
  case 10:
    primaryManufacturedPriceThreshold = 0x4e2;
    secondaryManufacturedPriceThreshold = 0x267;
    generalOfferPriceThreshold = 0x87;
    randomOfferPriceThreshold = 0x42;
    coalOfferPriceThreshold = 0x8d;
    ironOfferPriceThreshold = 0x90;
    oilOfferPriceThreshold = 0x6f;
    consortiumMembers[0] = 7;
    consortiumMembers[1] = 8;
    consortiumMembers[2] = 9;
    consortiumMembers[3] = 0xa;
    break;
  case 11:
    primaryManufacturedPriceThreshold = 0x514;
    secondaryManufacturedPriceThreshold = 0x276;
    generalOfferPriceThreshold = 0xbe;
    randomOfferPriceThreshold = 0x58;
    coalOfferPriceThreshold = 0x6c;
    ironOfferPriceThreshold = 0x8d;
    oilOfferPriceThreshold = 0x93;
    consortiumMembers[0] = 0xb;
    consortiumMembers[1] = 0xc;
    consortiumMembers[2] = 0xd;
    consortiumMembers[3] = 0xe;
    break;
  case 12:
    primaryManufacturedPriceThreshold = 0x546;
    secondaryManufacturedPriceThreshold = 0x285;
    generalOfferPriceThreshold = 0xaa;
    randomOfferPriceThreshold = 0x50;
    coalOfferPriceThreshold = 0x78;
    ironOfferPriceThreshold = 0x69;
    oilOfferPriceThreshold = 0x87;
    consortiumMembers[0] = 0xb;
    consortiumMembers[1] = 0xc;
    consortiumMembers[2] = 0xd;
    consortiumMembers[3] = 0xe;
    break;
  case 13:
    primaryManufacturedPriceThreshold = 0x578;
    secondaryManufacturedPriceThreshold = 0x294;
    generalOfferPriceThreshold = 0x96;
    randomOfferPriceThreshold = 0x48;
    coalOfferPriceThreshold = 0x84;
    ironOfferPriceThreshold = 0x7b;
    oilOfferPriceThreshold = 0x75;
    consortiumMembers[0] = 0xb;
    consortiumMembers[1] = 0xc;
    consortiumMembers[2] = 0xd;
    consortiumMembers[3] = 0xe;
    break;
  case 14:
    primaryManufacturedPriceThreshold = 0x5aa;
    secondaryManufacturedPriceThreshold = 0x2a3;
    generalOfferPriceThreshold = 0x82;
    randomOfferPriceThreshold = 0x40;
    coalOfferPriceThreshold = 0x90;
    ironOfferPriceThreshold = 0x81;
    oilOfferPriceThreshold = 0x72;
    consortiumMembers[0] = 0xb;
    consortiumMembers[1] = 0xc;
    consortiumMembers[2] = 0xd;
    consortiumMembers[3] = 0xe;
    break;
  case 15:
    primaryManufacturedPriceThreshold = 0x5dc;
    secondaryManufacturedPriceThreshold = 0x2b2;
    generalOfferPriceThreshold = 0xb9;
    randomOfferPriceThreshold = 0x56;
    coalOfferPriceThreshold = 0x6f;
    ironOfferPriceThreshold = 0x93;
    oilOfferPriceThreshold = 0x96;
    consortiumMembers[0] = 0xf;
    consortiumMembers[1] = 0x10;
    consortiumMembers[2] = 0x11;
    consortiumMembers[3] = 0x12;
    break;
  case 16:
    primaryManufacturedPriceThreshold = 0x60e;
    secondaryManufacturedPriceThreshold = 0x2c1;
    generalOfferPriceThreshold = 0xa5;
    randomOfferPriceThreshold = 0x4e;
    coalOfferPriceThreshold = 0x7b;
    ironOfferPriceThreshold = 0x6c;
    oilOfferPriceThreshold = 0x8a;
    consortiumMembers[0] = 0xf;
    consortiumMembers[1] = 0x10;
    consortiumMembers[2] = 0x11;
    consortiumMembers[3] = 0x12;
    break;
  case 17:
    primaryManufacturedPriceThreshold = 0x640;
    secondaryManufacturedPriceThreshold = 0x2d0;
    generalOfferPriceThreshold = 0x91;
    randomOfferPriceThreshold = 0x46;
    coalOfferPriceThreshold = 0x87;
    ironOfferPriceThreshold = 0x78;
    oilOfferPriceThreshold = 0x7e;
    consortiumMembers[0] = 0xf;
    consortiumMembers[1] = 0x10;
    consortiumMembers[2] = 0x11;
    consortiumMembers[3] = 0x12;
    break;
  case 18:
    primaryManufacturedPriceThreshold = 0x672;
    secondaryManufacturedPriceThreshold = 0x2df;
    generalOfferPriceThreshold = 0x7d;
    randomOfferPriceThreshold = 0x3e;
    coalOfferPriceThreshold = 0x93;
    ironOfferPriceThreshold = 0x84;
    oilOfferPriceThreshold = 0x69;
    consortiumMembers[0] = 0xf;
    consortiumMembers[1] = 0x10;
    consortiumMembers[2] = 0x11;
    consortiumMembers[3] = 0x12;
    break;
  case 19:
    primaryManufacturedPriceThreshold = 0x6a4;
    secondaryManufacturedPriceThreshold = 0x2ee;
    generalOfferPriceThreshold = 0xb4;
    randomOfferPriceThreshold = 0x54;
    coalOfferPriceThreshold = 0x72;
    ironOfferPriceThreshold = 0x96;
    oilOfferPriceThreshold = 0x8d;
    consortiumMembers[0] = 0x13;
    consortiumMembers[1] = 0x14;
    consortiumMembers[2] = 0x15;
    consortiumMembers[3] = 0x16;
    break;
  case 20:
    primaryManufacturedPriceThreshold = 0x6d6;
    secondaryManufacturedPriceThreshold = 0x2fd;
    generalOfferPriceThreshold = 0xa0;
    randomOfferPriceThreshold = 0x4c;
    coalOfferPriceThreshold = 0x7e;
    ironOfferPriceThreshold = 0x6f;
    oilOfferPriceThreshold = 0x81;
    consortiumMembers[0] = 0x13;
    consortiumMembers[1] = 0x14;
    consortiumMembers[2] = 0x15;
    consortiumMembers[3] = 0x16;
    break;
  case 21:
    primaryManufacturedPriceThreshold = 0x708;
    secondaryManufacturedPriceThreshold = 0x302;
    generalOfferPriceThreshold = 0x8c;
    randomOfferPriceThreshold = 0x44;
    coalOfferPriceThreshold = 0x8a;
    ironOfferPriceThreshold = 0x7b;
    oilOfferPriceThreshold = 0x75;
    consortiumMembers[0] = 0x13;
    consortiumMembers[1] = 0x14;
    consortiumMembers[2] = 0x15;
    consortiumMembers[3] = 0x16;
    break;
  case 22:
    primaryManufacturedPriceThreshold = 0x73a;
    secondaryManufacturedPriceThreshold = 0x311;
    generalOfferPriceThreshold = 0x78;
    randomOfferPriceThreshold = 0x3c;
    coalOfferPriceThreshold = 0x96;
    ironOfferPriceThreshold = 0x87;
    oilOfferPriceThreshold = 0x6c;
    consortiumMembers[0] = 0x13;
    consortiumMembers[1] = 0x14;
    consortiumMembers[2] = 0x15;
    consortiumMembers[3] = 0x16;
    break;
  }
}

// FUNCTION: IMPERIALISM 0x004e41c0
void TMinor::ReadFrom(TStream* stream) {
  TCountry::ReadFrom(stream);
  stream->ReadBytes(this->needCurrentByType, sizeof(this->needCurrentByType));
  SwapShortArrayBytes(this->needCurrentByType, 0x17);
  stream->ReadBytes(this->tradeOffersByResource, sizeof(this->tradeOffersByResource));
  SwapShortArrayBytes(this->tradeOffersByResource, 0x17);
  stream->ReadBytes(this->grantAmountsByResource, sizeof(this->grantAmountsByResource));
  SwapShortArrayBytes(this->grantAmountsByResource, 0x17);
  stream->ReadBytes(&this->primaryManufacturedPriceThreshold, 2);
  stream->ReadBytes(&this->secondaryManufacturedPriceThreshold, 2);
  stream->ReadBytes(&this->generalOfferPriceThreshold, 2);
  stream->ReadBytes(&this->randomOfferPriceThreshold, 2);
  stream->ReadBytes(&this->coalOfferPriceThreshold, 2);
  stream->ReadBytes(&this->ironOfferPriceThreshold, 2);
  stream->ReadBytes(&this->oilOfferPriceThreshold, 2);
  stream->ReadBytes(&this->primaryManufacturedRequest, 2);
  stream->ReadBytes(&this->secondaryManufacturedRequest, 2);
  stream->ReadBytes(&this->primaryManufacturedRequestFulfilledAmount, 2);
  stream->ReadBytes(&this->secondaryManufacturedRequestFulfilledAmount, 2);
  stream->ReadBytes(consortiumMembers, 8);
  SwapShortArrayBytes(consortiumMembers, 4);
  if (g_nSaveFormatVersion >= 0x3a) {
    stream->ReadBytes(independentResourceCountByType, 0x2e);
    SwapShortArrayBytes(independentResourceCountByType, 0x17);
  }
}

// FUNCTION: IMPERIALISM 0x004e4390
void TMinor::WriteTo(TStream* stream) {
  TCountry::WriteTo(stream);
  WriteShortArrayElems(stream, this->needCurrentByType, 0x17);
  WriteShortArrayElems(stream, this->tradeOffersByResource, 0x17);
  WriteShortArrayElems(stream, this->grantAmountsByResource, 0x17);
  stream->WriteBytes(&this->primaryManufacturedPriceThreshold, 2);
  stream->WriteBytes(&this->secondaryManufacturedPriceThreshold, 2);
  stream->WriteBytes(&this->generalOfferPriceThreshold, 2);
  stream->WriteBytes(&this->randomOfferPriceThreshold, 2);
  stream->WriteBytes(&this->coalOfferPriceThreshold, 2);
  stream->WriteBytes(&this->ironOfferPriceThreshold, 2);
  stream->WriteBytes(&this->oilOfferPriceThreshold, 2);
  stream->WriteBytes(&this->primaryManufacturedRequest, 2);
  stream->WriteBytes(&this->secondaryManufacturedRequest, 2);
  stream->WriteBytes(&this->primaryManufacturedRequestFulfilledAmount, 2);
  stream->WriteBytes(&this->secondaryManufacturedRequestFulfilledAmount, 2);
  WriteShortArrayElems(stream, consortiumMembers, 4);
  WriteShortArrayElems(stream, independentResourceCountByType, 0x17);
}

// True when `policyCode` matches one of the four saved diplomacy nation slots.
// FUNCTION: IMPERIALISM 0x004e45f0
bool TMinor::IsInConsortiumWith(short policyCode) {
  bool result = false;
  if (policyCode == consortiumMembers[0] || policyCode == consortiumMembers[1] ||
      policyCode == consortiumMembers[2] || policyCode == consortiumMembers[3]) {
    result = true;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004e4630
short TMinor::GetAmtUnsold(short resourceKind) {
  short sum = static_cast<short>(this->needCurrentByType[resourceKind] +
                                 this->grantAmountsByResource[resourceKind]);
  if (sum < 0) {
    sum = 0;
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e4660
short TMinor::GetStockpile(short resourceKind) {
  return this->needCurrentByType[resourceKind];
}

// FUNCTION: IMPERIALISM 0x004e4680
short TMinor::GetTradeOffersFor(short resourceKind) {
  return this->tradeOffersByResource[resourceKind];
}

// FUNCTION: IMPERIALISM 0x004e46a0
void TMinor::InitializeTradeStatus(void) {
  secondaryManufacturedRequest = -10;
  primaryManufacturedRequestFulfilledAmount = 0;
  secondaryManufacturedRequestFulfilledAmount = 0;
  int i;
  for (i = 0; i < kResourceKindCount; ++i) {
    tradeOffersByResource[i] = 0;
    grantAmountsByResource[i] = 0;
    independentResourceCountByType[i] = 0;
    foreignControlledResourceYieldByType[i] = 0;
    needCurrentByType[i] = 0;
    memset(&foreignControlledResourceYieldByTypeAndMajorNation[i], 0,
           sizeof(TMinorForeignResourceYieldByMajorNation));
  }
  needCurrentByType[7] = 2;

  int tileIndex;
  for (tileIndex = 0; static_cast<short>(tileIndex) < kStrategicTileCount; ++tileIndex) {
    if (g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag == this->nationSlot) {
      short tileGreatPower =
          g_pGlobalMapState->terrainStateTable[tileIndex].secondaryOwnerNationTag;
      if (tileGreatPower == -1) {
        for (int edge = 0; edge < 2; ++edge) {
          char resourceType =
              g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge];
          if (g_pGlobalMapState->terrainStateTable[tileIndex].gateFlag != 0xf &&
              resourceType != -1) {
            ++needCurrentByType[static_cast<int>(resourceType)];
            ++independentResourceCountByType[static_cast<int>(resourceType)];
          }
        }
      } else {
        for (int edge = 0; edge < 2; ++edge) {
          char resourceType =
              g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edge];
          if (resourceType != -1) {
            short yieldLevel =
                static_cast<char>(g_pGlobalMapState->FindResourceCapabilityRequirementLevelByType(
                    static_cast<short>(tileIndex), resourceType));
            foreignControlledResourceYieldByType[static_cast<int>(resourceType)] += yieldLevel;
            foreignControlledResourceYieldByTypeAndMajorNation[static_cast<int>(resourceType)]
                .amountByMajorNation[tileGreatPower] += yieldLevel;
            needCurrentByType[static_cast<int>(resourceType)] += yieldLevel;
          }
        }
      }
    }
  }

  for (int power = 0; power < 7; ++power) {
    if (g_apTerrainTypeDescriptorTable[power] != 0) {
      short goldYieldControlledByPower =
          foreignControlledResourceYieldByTypeAndMajorNation[kResourceGold]
              .amountByMajorNation[power];
      if (goldYieldControlledByPower != 0) {
        g_apNationStates[power]->AddOverseasProfitFrom(
            g_pDiplomacyTurnStateManager
                    ->relationStandingScores[this->nationSlot * kNationSlotCount + power] *
                goldYieldControlledByPower * 200 / 255,
            kResourceGold, this->nationSlot);
      }
      short gemYieldControlledByPower =
          foreignControlledResourceYieldByTypeAndMajorNation[kResourceGems]
              .amountByMajorNation[power];
      if (gemYieldControlledByPower != 0) {
        g_apNationStates[power]->AddOverseasProfitFrom(
            g_pDiplomacyTurnStateManager
                    ->relationStandingScores[this->nationSlot * kNationSlotCount + power] *
                gemYieldControlledByPower * 500 / 255,
            kResourceGems, this->nationSlot);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e49b0
void TMinor::PurchaseItem(short resourceKind, short amount, short price) {
  short resourceSlot = resourceKind;
  short deltaShort = amount;

  if (deltaShort >= 1 && resourceSlot >= 0xd && resourceSlot <= 0x10) {
    if (resourceSlot == this->primaryManufacturedRequest) {
      this->primaryManufacturedRequestFulfilledAmount = deltaShort;
    } else if (resourceSlot == this->secondaryManufacturedRequest) {
      this->secondaryManufacturedRequestFulfilledAmount = deltaShort;
    }
  } else if (resourceSlot < 0 || resourceSlot > 6) {
    if (resourceSlot == 7) {
      this->grantAmountsByResource[7] =
          static_cast<short>(this->grantAmountsByResource[7] + deltaShort);
    }
  } else {
    this->grantAmountsByResource[resourceSlot] =
        static_cast<short>(this->grantAmountsByResource[resourceSlot] + deltaShort);
    if (this->foreignControlledResourceYieldByType[resourceSlot] != 0) {
      for (int majorNationSlot = 0; majorNationSlot < kMajorNationCount; ++majorNationSlot) {
        if (g_apTerrainTypeDescriptorTable[majorNationSlot] == 0) {
          continue;
        }
        short linkValue = this->foreignControlledResourceYieldByTypeAndMajorNation[resourceSlot]
                              .amountByMajorNation[majorNationSlot];
        if (linkValue == 0) {
          continue;
        }

        short needCurrent = this->needCurrentByType[resourceSlot];
        short standing =
            g_pDiplomacyTurnStateManager
                ->relationStandingScores[this->nationSlot * kNationSlotCount + majorNationSlot];
        int negDelta = -static_cast<int>(deltaShort);
        int intFactor = negDelta;
        if (linkValue < negDelta) {
          intFactor = linkValue;
        }

        float floatAmount = static_cast<float>(linkValue) / static_cast<float>(needCurrent);
        floatAmount = floatAmount * static_cast<float>(standing);
        floatAmount = floatAmount * static_cast<float>(price);
        floatAmount = floatAmount * static_cast<float>(deltaShort);
        floatAmount *= g_ApplyIndexedResourceDeltaScale;
        float integerAmount =
            static_cast<float>(intFactor * static_cast<int>(standing) * price / 255);
        int integerGrantAmount = static_cast<int>(integerAmount);
        int grantAmount = static_cast<int>(floatAmount);
        if (integerGrantAmount > grantAmount) {
          grantAmount = integerGrantAmount;
        }
        g_apNationStates[majorNationSlot]->AddOverseasProfitFrom(grantAmount, resourceSlot,
                                                                 this->nationSlot);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e4bd0
void TMinor::SetTradeBids(void) {
  short savedPredicate = this->primaryManufacturedRequest;
  short proposalWeight = 0;
  if (this == 0 || this->encodedNationSlot <= 99 || this->encodedNationSlot >= 200) {
    int randomBucket = static_cast<int>(rand()) % 100;
    int resourceType = 0;
    if (randomBucket < 0x19) {
      resourceType = 0;
    } else if (randomBucket < 0x32) {
      resourceType = 1;
    } else {
      resourceType = ((0x4a < randomBucket) - 1 & 0xfffffffb) + 7;
    }

    proposalWeight = g_pTradeMgr->GetPrice(resourceType);
    if (this->randomOfferPriceThreshold < proposalWeight) {
      this->tradeOffersByResource[resourceType] = this->needCurrentByType[resourceType];
    }

    for (int policySlot = 0; policySlot < 8; ++policySlot) {
      proposalWeight = g_pTradeMgr->GetPrice(policySlot);
      if (this->generalOfferPriceThreshold < proposalWeight) {
        this->tradeOffersByResource[policySlot] = this->needCurrentByType[policySlot];
      }
    }

    proposalWeight = g_pTradeMgr->GetPrice(3);
    if (this->coalOfferPriceThreshold < proposalWeight) {
      this->tradeOffersByResource[3] = this->needCurrentByType[3];
    } else if (this->foreignControlledResourceYieldByType[3] != 0) {
      this->tradeOffersByResource[3] = this->foreignControlledResourceYieldByType[3];
    }

    proposalWeight = g_pTradeMgr->GetPrice(4);
    if (this->ironOfferPriceThreshold < proposalWeight) {
      this->tradeOffersByResource[4] = this->needCurrentByType[4];
    } else if (this->foreignControlledResourceYieldByType[4] != 0) {
      this->tradeOffersByResource[4] = this->foreignControlledResourceYieldByType[4];
    }

    proposalWeight = g_pTradeMgr->GetPrice(6);
    if (this->oilOfferPriceThreshold < proposalWeight) {
      this->tradeOffersByResource[6] = this->needCurrentByType[6];
    } else if (this->foreignControlledResourceYieldByType[6] != 0) {
      this->tradeOffersByResource[6] = this->foreignControlledResourceYieldByType[6];
    }

    if (this->tradeOffersByResource[0] == 0) {
      this->tradeOffersByResource[0] = this->foreignControlledResourceYieldByType[0];
    }
    if (this->tradeOffersByResource[1] == 0) {
      this->tradeOffersByResource[1] = this->foreignControlledResourceYieldByType[1];
    }
    if (this->tradeOffersByResource[2] == 0) {
      this->tradeOffersByResource[2] = this->foreignControlledResourceYieldByType[2];
    }
  }

  if (savedPredicate == this->primaryManufacturedRequest) {
    short rolledPredicate = this->primaryManufacturedRequest;
    do {
      int roll = static_cast<int>(rand()) % 100;
      if (roll < 0x1e) {
        rolledPredicate = 0xd;
      } else if (roll < 0x3c) {
        rolledPredicate = 0xe;
      } else {
        rolledPredicate = static_cast<short>((0x59 < roll) + 0xf);
      }
    } while (rolledPredicate == this->primaryManufacturedRequest);
    proposalWeight = g_pTradeMgr->GetPrice(rolledPredicate);
    if (this->primaryManufacturedPriceThreshold < proposalWeight) {
      this->primaryManufacturedRequest = -10;
    } else {
      this->primaryManufacturedRequest = rolledPredicate;
    }
  }

  this->secondaryManufacturedRequest = -10;
  int candidatePredicate = 0xd;
  do {
    proposalWeight = g_pTradeMgr->GetPrice(candidatePredicate);
    if (proposalWeight < this->secondaryManufacturedPriceThreshold &&
        candidatePredicate != this->primaryManufacturedRequest) {
      this->secondaryManufacturedRequest = static_cast<short>(candidatePredicate);
      candidatePredicate = 0x11;
    }
    ++candidatePredicate;
  } while (candidatePredicate < 0x11);

  if (this->primaryManufacturedRequest != -10) {
    this->tradeOffersByResource[this->primaryManufacturedRequest] = -1;
  }
  if (this->secondaryManufacturedRequest != -10) {
    this->tradeOffersByResource[this->secondaryManufacturedRequest] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x004e4ee0
bool TMinor::StillBuyingItem(ResourceKindStorage resourceKind) {
  if (resourceKind > kResourceFuel && resourceKind < kResourceGrain) {
    if (resourceKind == this->primaryManufacturedRequest) {
      return this->primaryManufacturedRequestFulfilledAmount == 0;
    }
    if (resourceKind == this->secondaryManufacturedRequest) {
      return this->secondaryManufacturedRequestFulfilledAmount == 0;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x004e4f50
bool TMinor::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                               ResourceKindStorage resourceKind) {
  if (!this->StillBuyingItem(resourceKind)) {
    return false;
  }

  g_pTradeMgr->SetDealResults(this->nationSlot, targetNationSlot, amount, price, resourceKind, 1,
                              false);
  return false;
}

// FUNCTION: IMPERIALISM 0x004e4fa0
void TMinor::SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) {
  short targetNationSlot = static_cast<short>(nationSlot);
  short policyValue = tradePolicy;
  if (targetNationSlot != this->nationSlot) {
    if (policyValue != this->needLevelByNation[targetNationSlot]) {
      this->needLevelByNation[targetNationSlot] = policyValue;
      if (policyValue == 300) {
        this->DeportCiviliansIn(-1, false);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e4ff0
bool TMinor::WouldAcceptOffer(NationSlot targetNationSlot,
                              DiplomacyProposalCodeStorage proposalCode) {
  if (proposalCode != kDiplomacyProposalJoinEmpire || this->encodedNationSlot != -1) {
    return false;
  }

  const int source = this->nationSlot;
  short standing = g_pDiplomacyTurnStateManager
                       ->relationStandingScores[source * kNationSlotCount + targetNationSlot];
  if (standing <= 0xf9) {
    return false;
  }

  bool canPropose = true;
  short* peerStandingRow =
      &g_pDiplomacyTurnStateManager->relationStandingScores[source * kNationSlotCount];
  for (int peerSlot = 0; peerSlot < 7; ++peerSlot) {
    if (g_apTerrainTypeDescriptorTable[peerSlot] != 0 && peerSlot != targetNationSlot) {
      int delta = abs(static_cast<int>(peerStandingRow[peerSlot]) - static_cast<int>(standing));
      if (delta < 10) {
        canPropose = false;
      }
    }
  }
  return canPropose;
}

// FUNCTION: IMPERIALISM 0x004e50d0
void TMinor::AddOfferFrom(NationSlot sourceNationSlot, DiplomacyProposalCodeStorage proposalCode) {
  NationSlot targetNation = sourceNationSlot;
  if (proposalCode == kDiplomacyProposalJoinEmpire) {
    bool canPropose = 0;
    if (this->encodedNationSlot == -1) {
      canPropose = this->WouldAcceptOffer(targetNation, proposalCode);
    }
    if (canPropose != 0) {
      if (!g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(this->nationSlot,
                                                                       targetNation)) {
        this->ChangeMaster(targetNation, 1);
        g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireAccepted, this->nationSlot,
                                   targetNation, false);
        return;
      }
      g_apNationStates[targetNation]->AddOfferFrom(
          this->nationSlot, kDiplomacyProposalJoinEmpireWithWarEntanglements);
      g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireAccepted, this->nationSlot,
                                 targetNation, false);
      return;
    }
    if (g_apNationStates[targetNation] != 0) {
      g_apNationStates[targetNation]->AddNoticeFrom(this->nationSlot,
                                                    -static_cast<int>(proposalCode));
    }
    g_pNewsMgr->AddTreatyEvent(kInterNationEventJoinEmpireRejected, targetNation, this->nationSlot,
                               false);
    return;
  }

  if (proposalCode == kDiplomacyProposalNonAggressionPact) {
    if (this->encodedNationSlot == -1) {
      g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
          this->nationSlot, targetNation, kDiplomacyRelationshipNonAggressionPact);
      if (g_apNationStates[targetNation] != 0) {
        g_apNationStates[targetNation]->AddNoticeFrom(this->nationSlot, proposalCode);
      }
      g_pNewsMgr->AddTreatyEvent(kInterNationEventNonAggressionPactAccepted, this->nationSlot,
                                 targetNation, false);
    }
    return;
  }

  if (proposalCode == kDiplomacyProposalPeaceTreaty && this->encodedNationSlot == -1) {
    g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
        this->nationSlot, targetNation, kDiplomacyRelationshipPeace);
    if (g_apNationStates[targetNation] != 0) {
      g_apNationStates[targetNation]->AddNoticeFrom(this->nationSlot, proposalCode);
    }
    g_pNewsMgr->AddTreatyEvent(kInterNationEventPeaceTreatyAccepted, this->nationSlot, targetNation,
                               false);
  }
}

// FUNCTION: IMPERIALISM 0x004e5300
void TMinor::AddNoticeFrom(short sourceNation, short actionCode) {
  if (actionCode == kDiplomacyProposalDeclareWar) {
    this->KillEnemyCiviliansIn(-1);
    this->KillBoycottedForeignCompanies();
  }
}

// FUNCTION: IMPERIALISM 0x004e5340
void TMinor::BecomeProtectorateOf(int targetNationSlot) {
  short decodedNationSlot = this->encodedNationSlot;
  if (decodedNationSlot >= 200) {
    decodedNationSlot = static_cast<short>(decodedNationSlot - 200);
  } else if (decodedNationSlot >= 100) {
    decodedNationSlot = static_cast<short>(decodedNationSlot - 100);
  } else {
    decodedNationSlot = this->nationSlot;
  }
  this->HandleNetworkPortConstructionOrder(targetNationSlot);

  if (this->encodedNationSlot < 200) {
    this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);

    for (int eligibleNationSlot = 0; eligibleNationSlot < kNationSlotCount; ++eligibleNationSlot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(eligibleNationSlot)) &&
          eligibleNationSlot != this->nationSlot && eligibleNationSlot != targetNationSlot) {
        TCountry* terrain = g_apTerrainTypeDescriptorTable[eligibleNationSlot];
        terrain->NewStatusFor(this->nationSlot, 100);
      }
    }
    g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

    for (int majorNationSlot = 0; majorNationSlot < kMajorNationCount; ++majorNationSlot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(majorNationSlot))) {
        TGreatPower* majorNation = g_apNationStates[majorNationSlot];
        if (majorNation->diplomacyEligibility == 0) {
          majorNation->AddNoticeFrom(this->nationSlot, kDiplomacyProposalDeclareWar);
        }
        g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCode(
            this->nationSlot, majorNationSlot, kDiplomacyRelationshipWar, 0);
        g_pDiplomacyTurnStateManager->SetRelationship(this->nationSlot, majorNationSlot, 0x31);
      }
    }

    for (int minorSlot = 7; minorSlot < kNationSlotCount; ++minorSlot) {
      g_pDiplomacyTurnStateManager->SetRelationship(this->nationSlot, minorSlot, 0x6e);
    }
  } else {
    TGreatPower* targetMajor = g_apNationStates[decodedNationSlot];
    targetMajor->AddNoticeFrom(this->nationSlot, 0x13c);
    g_pNewsMgr->AddTreatyEvent(kInterNationEventMinorEmpireAffiliationChanged, decodedNationSlot,
                               this->nationSlot, false);

    for (int resetNationSlot = 0; resetNationSlot < kNationSlotCount; ++resetNationSlot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(resetNationSlot))) {
        g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
            this->nationSlot, resetNationSlot, kDiplomacyRelationshipPeace);
        g_pDiplomacyTurnStateManager->SetRelationship(this->nationSlot, resetNationSlot, 0x5a);
      }
    }

    short ownedRegionIds[20];
    int index;
    for (index = 0; index < 20; ++index) {
      ownedRegionIds[index] = -1;
    }

    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      short regionId = static_cast<short>(this->ownedRegionList->At(oneBasedIndex));
      ownedRegionIds[oneBasedIndex] = regionId;
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }

    for (index = 0; index < 20; ++index) {
      int regionId = ownedRegionIds[index];
      if (regionId == -1) {
        continue;
      }
      short regionOwner = g_pMapContextActionManager->perTileOwnerNationCodeCache[regionId];
      if (regionOwner == this->nationSlot || regionOwner == decodedNationSlot) {
        g_pGlobalMapState->ChangeProvinceOwner(static_cast<short>(regionId), decodedNationSlot);
      }
    }

    this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);
    for (int linkNationSlot = 0; linkNationSlot < kNationSlotCount; ++linkNationSlot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(linkNationSlot)) &&
          linkNationSlot != this->nationSlot && linkNationSlot != targetNationSlot) {
        TCountry* terrain = g_apTerrainTypeDescriptorTable[linkNationSlot];
        terrain->NewStatusFor(this->nationSlot, 100);
      }
    }
    g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);
  }

  for (int standingNationSlot = 0; standingNationSlot < kMajorNationCount; ++standingNationSlot) {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(standingNationSlot))) {
      if (standingNationSlot == targetNationSlot) {
        this->SetTradePolicyTo(static_cast<NationSlot>(standingNationSlot), 100);
        g_apNationStates[standingNationSlot]->SetTradePolicyTo(this->nationSlot, 100);
        g_apNationStates[standingNationSlot]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
            this->nationSlot, static_cast<unsigned short>(-1));
      } else {
        this->SetTradePolicyTo(static_cast<NationSlot>(standingNationSlot), 300);
        g_apNationStates[standingNationSlot]->SetTradePolicyTo(this->nationSlot, 300);
      }
    }
  }

  this->ClearTileActivityOverlayByProvinceId(-1);
  TGreatPower* previousOwner = g_apNationStates[decodedNationSlot];
  if (previousOwner->pendingActionStatus.byAction[6] < '3') {
    previousOwner->SetNationPendingActionStateAndPayload(6, this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e5730
void TMinor::HandleNetworkPortConstructionOrder(int nationId) {
  unsigned char nationTileFlags = static_cast<unsigned char>(
      g_pGlobalMapState->terrainStateTable[static_cast<short>(this->homeTileIndex)].activeFlags);
  if ((nationTileFlags >> 2 & 1) != 0) {
    return;
  }

  TTown* marker = new TTown();
  marker->ITown("", this->homeTileIndex, true, static_cast<short>(nationId));
  marker->activeFlag = true;
  g_pGlobalMapState->SetTileTransportFlags(static_cast<short>(this->homeTileIndex), 0x15);
  TGreatPower* targetNation = g_apNationStates[nationId];
  targetNation->townMarkerList->AddTail(marker);
}

// FUNCTION: IMPERIALISM 0x004e5840
void TMinor::BecomeColonyOf(int targetNationSlot) {
  // MATCH: the original inlines the whole TCountry::BecomeColonyOf (0x4d7c90) body here
  // rather than calling it, so the base work is transcribed instead of delegated.
  this->encodedNationSlot = static_cast<short>(targetNationSlot + 200);
  this->SetTradePolicyTo(static_cast<NationSlot>(targetNationSlot), 100);

  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot)) &&
        nationSlot != this->nationSlot && nationSlot != targetNationSlot) {
      g_apTerrainTypeDescriptorTable[nationSlot]->NewStatusFor(this->nationSlot, 200);
    }
  }

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

  TGreatPower* targetNation = g_apNationStates[targetNationSlot];
  targetNation->AddColony(this->nationSlot);
  this->ChangeArmyOwnership(targetNationSlot);
  this->SetBoycottPoliciesToMatch(static_cast<NationSlot>(targetNationSlot));
  g_pDiplomacyTurnStateManager->SetRelationshipsToMatch(this->nationSlot, targetNationSlot);
  this->KillEnemyCiviliansIn(-1);
  this->DeportCiviliansIn(-1, false);

  if (targetNation->pendingActionStatus.byAction[10] < '3') {
    targetNation->SetNationPendingActionStateAndPayload(10, this->nationSlot);
  }

  g_pNewsMgr->AddTreatyEvent(kInterNationEventNationJoinedEmpire, targetNationSlot,
                             this->nationSlot, false);
}

// FUNCTION: IMPERIALISM 0x004e59d0
void TMinor::RegainIndependence(void) {
  short decodedSlot;
  if (this->encodedNationSlot < 200) {
    if (this->encodedNationSlot < 100) {
      decodedSlot = this->nationSlot;
    } else {
      decodedSlot = static_cast<short>(this->encodedNationSlot - 100);
    }
  } else {
    decodedSlot = static_cast<short>(this->encodedNationSlot - 200);
  }
  this->encodedNationSlot = -1;
  this->AssimilateTroopsOf(decodedSlot);
  int nationSlot = 0;
  do {
    this->SetTradePolicyTo(static_cast<NationSlot>(nationSlot), 100);
    ++nationSlot;
  } while (nationSlot < kNationSlotCount);
}

// FUNCTION: IMPERIALISM 0x004e5a40
void TMinor::SetBoycottPoliciesToMatch(int targetNationSlot) {
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (!g_pDiplomacyTurnStateManager->IsNationPairAtWar(targetNationSlot, nationSlot) &&
        (nationSlot == this->nationSlot ||
         (g_apNationStates[targetNationSlot] != 0 &&
          g_apNationStates[targetNationSlot]->colonyBoycottFlags[nationSlot] == 0))) {
      this->SetTradePolicyTo(static_cast<NationSlot>(nationSlot), 100);
    } else {
      this->SetTradePolicyTo(static_cast<NationSlot>(nationSlot), 300);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5ac0
void TMinor::ClearTileActivityOverlayByProvinceId(int provinceId) {
  TTerrainStateRecord* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId == -1) {
    int ownedCount = this->ownedRegionList->GetSize();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->At(oneBasedIndex);
      Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          short tileId = regionRecord->linkedTileIndices[linkedIndex];
          terrainTiles[tileId].secondaryOwnerNationTag = -1;
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetSize();
    }
    return;
  }

  Province* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      short tileId = regionRecord->linkedTileIndices[linkedIndex];
      terrainTiles[tileId].secondaryOwnerNationTag = -1;
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5be0
void TMinor::KillBoycottedForeignCompanies(void) {
  int majorSlot;
  char needLevel300ByMajorSlot[kMajorNationCount];
  for (majorSlot = 0; majorSlot < kMajorNationCount; ++majorSlot) {
    needLevel300ByMajorSlot[majorSlot] = (this->needLevelByNation[majorSlot] == 300) ? 1 : 0;
  }

  char notifyMajorSlots[kMajorNationCount] = {0};
  TTerrainStateRecord* terrainTiles = g_pGlobalMapState->terrainStateTable;

  int ownedCount = this->ownedRegionList->GetSize();
  int oneBasedIndex = 1;
  while (oneBasedIndex <= ownedCount) {
    int regionId = this->ownedRegionList->At(oneBasedIndex);
    Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
    if (regionRecord->linkedRegionCount > 0) {
      int linkedIndex = 0;
      while (linkedIndex < regionRecord->linkedRegionCount) {
        short tileId = regionRecord->linkedTileIndices[linkedIndex];
        int tileNation = terrainTiles[tileId].secondaryOwnerNationTag;
        if (tileNation != -1 && needLevel300ByMajorSlot[tileNation] != 0) {
          notifyMajorSlots[tileNation] = 1;
          terrainTiles[tileId].secondaryOwnerNationTag = -1;
        }
        linkedIndex++;
      }
    }
    oneBasedIndex++;
    ownedCount = this->ownedRegionList->GetSize();
  }

  for (majorSlot = 0; majorSlot < kMajorNationCount; ++majorSlot) {
    if (g_apNationStates[majorSlot] != 0 && notifyMajorSlots[majorSlot] != 0) {
      g_apNationStates[majorSlot]->AddNoticeFrom(this->nationSlot, 0x137);
      g_pNewsMgr->AddTreatyEvent(kInterNationEventMinorTerritoryRelationshipAffected, majorSlot,
                                 this->nationSlot, false);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5d90
void TMinor::KillEnemyCiviliansIn(int provinceId) {
  NationSlot ownerNationSlot;
  if (provinceId != -1) {
    ownerNationSlot = g_pGlobalMapState->cityScoreTable[provinceId].ownerNationCode;
  } else if (this->encodedNationSlot >= 200) {
    ownerNationSlot = this->encodedNationSlot - 200;
  } else if (this->encodedNationSlot >= 100) {
    ownerNationSlot = this->encodedNationSlot - 100;
  } else {
    ownerNationSlot = this->nationSlot;
  }

  char relationMaskByNation[kMajorNationCount];
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    relationMaskByNation[nationSlot] = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 && nationSlot != ownerNationSlot &&
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(ownerNationSlot, nationSlot)) {
      relationMaskByNation[nationSlot] = 1;
    }
  }

  TTerrainStateRecord* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId != -1) {
    Province* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
    if (regionRecord->linkedRegionCount > 0) {
      int linkedIndex = 0;
      while (linkedIndex < regionRecord->linkedRegionCount) {
        short tileId = regionRecord->linkedTileIndices[linkedIndex];
        TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder;
        while (orderNode != 0) {
          TUnit* nextNode = orderNode->nextAtLocation;
          int orderOwnerNationSlot = orderNode->ownerNationSlot;
          if (relationMaskByNation[orderOwnerNationSlot] != 0) {
            if (orderNode->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
              TGreatPower* ownerNation = g_apNationStates[orderOwnerNationSlot];
              orderNode->MoveTo(static_cast<short>(ownerNation->homeTileIndex));
            } else {
              orderNode->Vaporize();
              orderNode->Free();
            }
          }
          orderNode = nextNode;
        }
        linkedIndex++;
      }
    }
    return;
  }

  int ownedCount = this->ownedRegionList->GetSize();
  int oneBasedIndex = 1;
  while (oneBasedIndex <= ownedCount) {
    int regionId = this->ownedRegionList->At(oneBasedIndex);
    Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
    if (regionRecord->linkedRegionCount > 0) {
      int linkedIndex = 0;
      while (linkedIndex < regionRecord->linkedRegionCount) {
        short tileId = regionRecord->linkedTileIndices[linkedIndex];
        TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder;
        while (orderNode != 0) {
          TUnit* nextNode = orderNode->nextAtLocation;
          int orderOwnerNationSlot = orderNode->ownerNationSlot;
          if (relationMaskByNation[orderOwnerNationSlot] != 0) {
            orderNode->Vaporize();
            orderNode->Free();
          }
          orderNode = nextNode;
        }
        linkedIndex++;
      }
    }
    oneBasedIndex++;
    ownedCount = this->ownedRegionList->GetSize();
  }
}

// FUNCTION: IMPERIALISM 0x004e6040
void TMinor::AssimilateTroopsOf(int priorOwnerNationSlot) {
  TSortedList* priorOwnerManager =
      g_apTerrainTypeDescriptorTable[priorOwnerNationSlot]->militaryUnitList;

  int ownedCount = this->ownedRegionList->GetSize();
  int oneBasedIndex = 1;
  while (oneBasedIndex <= ownedCount) {
    short regionId = static_cast<short>(this->ownedRegionList->At(oneBasedIndex));
    if (regionId < 0 || regionId >= kProvinceCount) {
      oneBasedIndex++;
      continue;
    }
    TMilitaryUnit* unitNode = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain;
    while (unitNode != 0) {
      TUnit* unit = unitNode;
      TMilitaryUnit* nextNode = static_cast<TMilitaryUnit*>(unitNode->nextAtLocation);
      if (unit->ownerNationSlot == priorOwnerNationSlot) {
        unit->ownerNationSlot = this->nationSlot;
        CPtrList* sourceList = &priorOwnerManager->listState;
        POSITION pos = sourceList->Find(unit, 0);
        if (pos != 0) {
          sourceList->RemoveAt(pos);
        }
        this->militaryUnitList->AddTail(unit);
      }
      unitNode = nextNode;
    }
    oneBasedIndex++;
    ownedCount = this->ownedRegionList->GetSize();
  }
}

// FUNCTION: IMPERIALISM 0x004e6150
void TMinor::DeportCiviliansIn(int provinceId, bool includeAllPolicyTargets) {
  if (!includeAllPolicyTargets) {
    this->KillBoycottedForeignCompanies();
  }

  NationSlot ownerNationSlot;
  if (provinceId == -1) {
    if (this->encodedNationSlot >= 200) {
      ownerNationSlot = this->encodedNationSlot - 200;
    } else if (this->encodedNationSlot >= 100) {
      ownerNationSlot = this->encodedNationSlot - 100;
    } else {
      ownerNationSlot = this->nationSlot;
    }
  } else {
    ownerNationSlot = g_pGlobalMapState->cityScoreTable[provinceId].ownerNationCode;
  }

  char relationMaskByNation[kMajorNationCount];
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    relationMaskByNation[nationSlot] = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 && nationSlot != ownerNationSlot &&
        (includeAllPolicyTargets ||
         g_pDiplomacyTurnStateManager->HasNationPairNeedLevel300(this->nationSlot, nationSlot))) {
      relationMaskByNation[nationSlot] = 1;
    }
  }

  TTerrainStateRecord* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId != -1) {
    Province* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
    if (regionRecord->linkedRegionCount > 0) {
      int linkedIndex = 0;
      while (linkedIndex < regionRecord->linkedRegionCount) {
        short tileId = regionRecord->linkedTileIndices[linkedIndex];
        TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder;
        while (orderNode != 0) {
          TUnit* nextNode = orderNode->nextAtLocation;
          int orderOwnerNationSlot = orderNode->ownerNationSlot;
          if (relationMaskByNation[orderOwnerNationSlot] != 0) {
            TGreatPower* ownerNation = g_apNationStates[orderOwnerNationSlot];
            short spawnTile = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
                static_cast<short>(ownerNation->homeTileIndex), false);
            if (spawnTile == -1) {
              orderNode->Vaporize();
              orderNode->Free();
            } else {
              orderNode->SetOrders(kUnitOrderIdle, -1);
              orderNode->MoveTo(spawnTile);
            }
          }
          orderNode = nextNode;
        }
        linkedIndex++;
      }
    }
    return;
  }

  int ownedCount = this->ownedRegionList->GetSize();
  int oneBasedIndex = 1;
  while (oneBasedIndex <= ownedCount) {
    int regionId = this->ownedRegionList->At(oneBasedIndex);
    Province* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
    if (regionRecord->linkedRegionCount > 0) {
      int linkedIndex = 0;
      while (linkedIndex < regionRecord->linkedRegionCount) {
        short tileId = regionRecord->linkedTileIndices[linkedIndex];
        TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder;
        while (orderNode != 0) {
          TUnit* nextNode = orderNode->nextAtLocation;
          int orderOwnerNationSlot = orderNode->ownerNationSlot;
          if (relationMaskByNation[orderOwnerNationSlot] != 0) {
            TGreatPower* ownerNation = g_apNationStates[orderOwnerNationSlot];
            short spawnTile = g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(
                static_cast<short>(ownerNation->homeTileIndex), false);
            if (spawnTile == -1) {
              orderNode->Vaporize();
              orderNode->Free();
            } else {
              orderNode->MoveTo(spawnTile);
            }
          }
          orderNode = nextNode;
        }
        linkedIndex++;
      }
    }
    oneBasedIndex++;
    ownedCount = this->ownedRegionList->GetSize();
  }
}

// FUNCTION: IMPERIALISM 0x004e64a0
void TMinor::LoseProvince(int regionId) {
  this->ownedRegionList->Delete(regionId);
  this->ClearTileActivityOverlayByProvinceId(regionId);
  this->KillEnemyCiviliansIn(regionId);
  this->DeportCiviliansIn(regionId, true);
}

// FUNCTION: IMPERIALISM 0x004e64f0
void TMinor::AddProvince(int regionId) {
  this->ownedRegionList->InsertLast(regionId);
}

// FUNCTION: IMPERIALISM 0x004e6520
void TMinor::ChangeArmyOwnership(int destinationNationSlot) {
  TSortedList* destinationManager =
      g_apTerrainTypeDescriptorTable[destinationNationSlot]->militaryUnitList;

  CIterator unitCursor(this->militaryUnitList);
  TUnit* unit = static_cast<TUnit*>(unitCursor.Reset());
  while (unitCursor.More() != 0) {
    unit->ownerNationSlot = static_cast<short>(destinationNationSlot);
    CPtrList* sourceList = &this->militaryUnitList->listState;
    POSITION pos = sourceList->Find(unit, 0);
    if (pos != 0) {
      sourceList->RemoveAt(pos);
    }
    destinationManager->AddTail(unit);
    unit = static_cast<TUnit*>(unitCursor.Advance());
  }
}
