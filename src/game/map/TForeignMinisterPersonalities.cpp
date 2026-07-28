#include "game/map/TForeignMinisterPersonalities.h"
#include "game/resource_domain_types.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/TMinisterBaseOrderArray.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/map/TSortByPriceList.h"
#include "game/core/TStream.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

namespace {

struct ResourcePriorityEntry {
  short resourceCode;
  short priority;
};

static __inline bool HasAdvancedTradeResource(const TForeignMinister* minister) {
  return g_pCityOrderCapabilityState->orderCapRows277[minister->ownerContextAt04->nationSlot]
             .techStatusByTechId[0x13] == 2;
}

static inline short MinShort(short a, short b) {
  return a < b ? a : b;
}

static inline void PreparePersonalityTradeBids(TForeignMinister* minister) {
  minister->InitializeTradeStatus();
  TGreatPower* owner = minister->ownerContextAt04;
  if (minister->diplomacyPhaseCounter18 >= minister->tradeBidRefreshInterval1a ||
      minister->WeNeedMoney() != 0) {
    owner->interiorMinister->PleaseBuildShip(minister->interiorOrderKind1c);
    minister->diplomacyPhaseCounter18 = 0;
  }
  minister->SetBuyPriorities();
  if (minister->interiorBidResource10 != -10) {
    short resourceCode = minister->interiorBidResource10;
    owner->SetItemPotentials(resourceCode, -1);
    minister->purchasePriorityByResource1e[resourceCode] = minister->interiorBidAmount12;
  }
  for (int index = 0; index < 4; ++index) {
    owner->SetItemPotentials(minister->preferredResourceSlots40[index], -1);
  }
}

static inline void AddSortedResourcePrice(TSortByPriceList* prices, short resourceCode) {
  ResourcePriorityEntry entry;
  entry.resourceCode = resourceCode;
  entry.priority = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceCode);
  prices->InsertCopiedRecordSortedByComparator(&entry);
}

static inline short GetSortedResourceCode(TSortByPriceList* prices, int oneBasedIndex) {
  ResourcePriorityEntry* entry =
      static_cast<ResourcePriorityEntry*>(prices->GetPtrListEntryByOneBasedIndex(oneBasedIndex));
  return entry->resourceCode;
}

static inline void SetTedStyleAdvancedResourceBid(TForeignMinister* minister, short threshold) {
  TGreatPower* owner = minister->ownerContextAt04;
  if (g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x10) > threshold &&
      g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(owner->nationSlot) == 0) {
    short available = owner->GetStockpile(kResourceArms);
    short amount = static_cast<short>(available / 10);
    if (amount > 2) {
      owner->SetItemPotentials(kResourceArms, amount);
    } else if (available > 6) {
      owner->SetItemPotentials(kResourceArms, 2);
    }
  }
}

} // namespace

// ===================== TTedForeignMinister (0x659d70) =====================

// SYNTHETIC: IMPERIALISM 0x00531130
// TTedForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x005311b0
// TTedForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTedForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005311d0
TTedForeignMinister::TTedForeignMinister() : TForeignMinister() {
  tradeBidRefreshInterval1a = 4;
  this->skillIndexC = 5;
}

// SYNTHETIC: IMPERIALISM 0x00531240
// TTedForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531290
void TTedForeignMinister::SetBuyPriorities() {
  if (!HasAdvancedTradeResource(this)) {
    if (ownerContextAt04->GetStockpile(kResourceIron) <
        ownerContextAt04->GetStockpile(kResourceCoal)) {
      preferredResourceSlots40[0] = 4;
      preferredResourceSlots40[2] = 3;
    } else {
      preferredResourceSlots40[0] = 3;
      preferredResourceSlots40[2] = 4;
    }
    preferredResourceSlots40[1] = 2;
    preferredResourceSlots40[3] = rand() < 0x3ffe ? 0 : 1;
    TForeignMinister::SetBuyPriorities();
    return;
  }

  short resources[4] = {2, 3, 4, 6};
  for (int i = 0; i < 3; ++i) {
    for (int j = i + 1; j < 4; ++j) {
      if (ownerContextAt04->GetStockpile(resources[j]) <
          ownerContextAt04->GetStockpile(resources[i])) {
        short swap = resources[i];
        resources[i] = resources[j];
        resources[j] = swap;
      }
    }
  }
  for (int resourceIndex = 0; resourceIndex < 3; ++resourceIndex) {
    preferredResourceSlots40[resourceIndex] = resources[resourceIndex];
  }
  preferredResourceSlots40[3] = rand() < 0x3ffe ? 0 : 1;
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00531550
void TTedForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = ownerContextAt04;
  short merchantCapacity = owner->merchantCapacity;
  short resourceAmount = owner->GetStockpile(kResourceHardware);
  if (owner->treasuryValue10 >= 0 && merchantCapacity > resourceAmount && resourceAmount < 10) {
    owner->SetItemPotentials(kResourceClothing, owner->GetStockpile(kResourceClothing));
    owner->SetItemPotentials(kResourceFurniture, owner->GetStockpile(kResourceFurniture));
  } else {
    short amount = MinShort(merchantCapacity, resourceAmount);
    owner->SetItemPotentials(kResourceHardware, amount);
    if (merchantCapacity > amount * 2) {
      owner->SetItemPotentials(kResourceClothing, owner->GetStockpile(kResourceClothing));
      owner->SetItemPotentials(kResourceFurniture, owner->GetStockpile(kResourceFurniture));
    }
  }
  SetTedStyleAdvancedResourceBid(this, 1500);
}

// FUNCTION: IMPERIALISM 0x00531770
void TTedForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                            short resourceCode) {
  if (purchasePriorityByResource1e[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(arg1, arg2, arg3, resourceCode);
    return;
  }
  TGreatPower* owner = ownerContextAt04;
  if (resourceCode == kResourceCoal) {
    if (tradePartnerEnabled49[3] != 0) {
      capabilityFlag16 = static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(3) / 2);
      tradePartnerEnabled49[3] = 0;
    }
    if (capabilityFlag16 >= arg2) {
      g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, arg2, arg3, 3, 0,
                                                       0);
      capabilityFlag16 = static_cast<short>(capabilityFlag16 - arg2);
    } else {
      g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, capabilityFlag16,
                                                       arg3, 3, 1, 0);
      capabilityFlag16 = 0;
    }
    return;
  }
  if (resourceCode == kResourceTimber || resourceCode == kResourceIron ||
      resourceCode == kResourceOil) {
    short available =
        static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
    short amount =
        available >= arg2
            ? arg2
            : static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
    g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3,
                                                     resourceCode, 0, 0);
    return;
  }
  if (resourceCode == kResourceCotton || resourceCode == kResourceWool) {
    short amount = owner->merchantCapacity < 15 ? 1 : (owner->merchantCapacity >= 30 ? 3 : 2);
    amount = MinShort(amount, arg2);
    short available =
        static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
    if (available < amount) {
      amount = static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
    }
    g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3,
                                                     resourceCode, 0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00531a10
void TTedForeignMinister::DoFirstTurnDiplomacy() {
  short selectedNations[4] = {0, 0, 0, 0};
  short selectedCount = 0;
  short attempts = 0;
  while (selectedCount < 4) {
    if (attempts > 15) {
      return;
    }
    ++attempts;
    short candidate = static_cast<short>(abs(rand()) % 0x10 + 7);
    bool duplicate = false;
    for (int index = 0; index < selectedCount; ++index) {
      if (selectedNations[index] == candidate) {
        duplicate = true;
      }
    }
    if (!duplicate &&
        !g_pGlobalMapState->TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(
            ownerContextAt04->nationSlot, candidate) &&
        g_apTerrainTypeDescriptorTable[candidate] != 0) {
      selectedNations[selectedCount] = candidate;
      ownerContextAt04->ApplyDiplomacyPolicyStateForTargetWithCostChecks(candidate, 0x133);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00531af0
void TTedForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x00531b10
void TTedForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] = 3;
}

// ===================== TBillForeignMinister (0x659e30) =====================

// SYNTHETIC: IMPERIALISM 0x00531b30
// TBillForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00531bc0
// TBillForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TBillForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00531be0
TBillForeignMinister::TBillForeignMinister() : TForeignMinister() {
  orderFlag80 = 0;
  field48 = 1;
  interiorOrderKind1c = 1;
  tradeBidRefreshInterval1a = 4;
  skillIndexC = 4;
}

// SYNTHETIC: IMPERIALISM 0x00531c50
// TBillForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531ca0
void TBillForeignMinister::ReadFrom(TStream* stream) {
  TForeignMinister::ReadFrom(stream);
  stream->ReadBytes(&orderFlag80, 1);
}

// FUNCTION: IMPERIALISM 0x00531ce0
void TBillForeignMinister::WriteTo(TStream* stream) {
  TForeignMinister::WriteTo(stream);
  stream->WriteBytes(&orderFlag80, 1);
}

// FUNCTION: IMPERIALISM 0x00531d20
void TBillForeignMinister::SetBuyPriorities() {
  bool hasAdvancedResource = HasAdvancedTradeResource(this);
  if (ownerContextAt04->GetStockpile(kResourceIron) <
      ownerContextAt04->GetStockpile(kResourceCoal)) {
    preferredResourceSlots40[0] = 4;
    preferredResourceSlots40[hasAdvancedResource ? 3 : 2] = 3;
  } else {
    preferredResourceSlots40[0] = 3;
    preferredResourceSlots40[hasAdvancedResource ? 3 : 2] = 4;
  }
  preferredResourceSlots40[1] = 2;
  if (hasAdvancedResource) {
    preferredResourceSlots40[2] = 6;
  } else {
    preferredResourceSlots40[3] = static_cast<short>(0xfff6);
  }
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00531e50
void TBillForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = ownerContextAt04;
  short targetAmount = owner->treasuryValue10 < 0 ? owner->merchantCapacity
                                                  : static_cast<short>(owner->merchantCapacity / 2);
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize14 = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short amounts[0x11] = {0};
  int selectedOrdinal = 3;
  int iteration = 0;
  while (targetAmount > 0 && iteration < targetAmount * 3) {
    short resourceCode = GetSortedResourceCode(prices, selectedOrdinal);
    if (amounts[resourceCode] < owner->GetStockpile(resourceCode)) {
      ++amounts[resourceCode];
      owner->SetItemPotentials(resourceCode, amounts[resourceCode]);
    }
    if (amounts[0x0d] + amounts[0x0e] + amounts[0x0f] >= targetAmount) {
      break;
    }
    --selectedOrdinal;
    if (selectedOrdinal == 0) {
      selectedOrdinal = 3;
    }
    ++iteration;
  }
  prices->ReleasePtrList();
  SetTedStyleAdvancedResourceBid(this, 1500);
}

// FUNCTION: IMPERIALISM 0x00532190
void TBillForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                             short resourceCode) {
  if (purchasePriorityByResource1e[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(arg1, arg2, arg3, resourceCode);
    return;
  }
  TGreatPower* owner = ownerContextAt04;
  short available;
  short amount;
  if (resourceCode == kResourceTimber) {
    if (g_pNationInteractionStateManager->QueryProposalWeightSlot4C(3) >= 105 &&
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(4) >= 105) {
      if (tradePartnerEnabled49[2] != 0) {
        capabilityFlag16 = static_cast<short>(owner->GetAvailableMerchantCapacity() / 3);
        if (capabilityFlag16 < 2) {
          capabilityFlag16 = 2;
        }
        tradePartnerEnabled49[2] = 0;
      }
      available = owner->GetAvailableMerchantCapacity();
      amount = MinShort(capabilityFlag16, available);
      if (amount >= arg2) {
        g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, arg2, arg3, 2, 0,
                                                         0);
        capabilityFlag16 = static_cast<short>(capabilityFlag16 - arg2);
        if (capabilityFlag16 < 0) {
          capabilityFlag16 = 0;
        }
      } else {
        g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3, 2,
                                                         1, 0);
        capabilityFlag16 = 0;
      }
    } else {
      available = owner->GetAvailableMerchantCapacity();
      amount = available >= arg2 ? arg2 : owner->GetAvailableMerchantCapacity();
      g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3, 2, 0,
                                                       0);
    }
    return;
  }
  if (resourceCode == kResourceCoal) {
    if (tradePartnerEnabled49[3] != 0) {
      capabilityFlag16 = static_cast<short>(owner->GetAvailableMerchantCapacity() / 2);
      tradePartnerEnabled49[3] = 0;
    }
    amount = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(4) < 105
                 ? arg2
                 : capabilityFlag16;
    amount = MinShort(amount, arg2);
    available = owner->GetAvailableMerchantCapacity();
    if (available >= amount) {
      g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3, 3, 0,
                                                       0);
      capabilityFlag16 = static_cast<short>(capabilityFlag16 - amount);
    } else {
      g_pNationInteractionStateManager->SetDealResults(
          owner->nationSlot, arg1, owner->GetAvailableMerchantCapacity(), arg3, 3, 1, 0);
      capabilityFlag16 = 0;
    }
    return;
  }
  if (resourceCode == kResourceIron || resourceCode == kResourceOil) {
    available = owner->GetAvailableMerchantCapacity();
    if (available >= arg2) {
      g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, arg2, arg3,
                                                       resourceCode, 0, 0);
      if (resourceCode == kResourceIron) {
        capabilityFlag16 = static_cast<short>(capabilityFlag16 - arg2);
      }
    } else {
      g_pNationInteractionStateManager->SetDealResults(
          owner->nationSlot, arg1, owner->GetAvailableMerchantCapacity(), arg3, resourceCode,
          resourceCode == kResourceIron, 0);
      if (resourceCode == kResourceIron) {
        capabilityFlag16 = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00532520
void TBillForeignMinister::DoFirstTurnDiplomacy() {
  short selectedNations[2] = {0, 0};
  short selectedCount = 0;
  short attempts = 0;
  while (selectedCount < 2) {
    if (attempts > 15) {
      return;
    }
    ++attempts;
    short candidate = static_cast<short>(abs(rand()) % 0x10 + 7);
    if ((selectedCount == 0 || selectedNations[0] != candidate) &&
        !g_pGlobalMapState->TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(
            ownerContextAt04->nationSlot, candidate) &&
        g_apTerrainTypeDescriptorTable[candidate] != 0) {
      selectedNations[selectedCount] = candidate;
      ownerContextAt04->ApplyDiplomacyPolicyStateForTargetWithCostChecks(candidate, 0x133);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005325e0
void TBillForeignMinister::DoSecondTurnDiplomacy() {
  short selectedCount = 0;
  for (short candidate = 7; candidate < 0x17 && selectedCount < 2; ++candidate) {
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
            ownerContextAt04->nationSlot, candidate) >= 1) {
      ownerContextAt04->SetTradePolicyTo(static_cast<NationSlot>(candidate), 0x5a);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00532650
void TBillForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] = 3;
  short nextLevel = static_cast<short>(city->GetBuildingType(2) + 2);
  city->productionAccum1fc[2] = static_cast<short>(city->productionAccum1fc[2] + nextLevel -
                                                   city->productionOrderTable1dc[2]);
  city->productionOrderTable1dc[2] = nextLevel;
  nextLevel = static_cast<short>(city->GetBuildingType(4) + 2);
  city->productionAccum1fc[4] = static_cast<short>(city->productionAccum1fc[4] + nextLevel -
                                                   city->productionOrderTable1dc[4]);
  city->productionOrderTable1dc[4] = nextLevel;
  city->SetOwnerNeedCapA6(static_cast<short>(city->GetOwnerNeedCapA6() + 2));
}

// ===================== TDiplomatForeignMinister (0x659f48) =====================

// SYNTHETIC: IMPERIALISM 0x005326e0
// TDiplomatForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00532760
// TDiplomatForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TDiplomatForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00532780
TDiplomatForeignMinister::TDiplomatForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x005327f0
// TDiplomatForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00532840
void TDiplomatForeignMinister::DoFirstTurnDiplomacy() {
  int roll = rand() % 100;
  short firstNation;
  if (roll < 25) {
    firstNation = 7;
  } else if (roll < 50) {
    firstNation = 11;
  } else if (roll < 75) {
    firstNation = 15;
  } else {
    firstNation = 19;
  }
  for (short nation = firstNation; nation < firstNation + 4; ++nation) {
    ownerContextAt04->ApplyDiplomacyPolicyStateForTargetWithCostChecks(nation, 0x133);
  }
}

// FUNCTION: IMPERIALISM 0x005328d0
void TDiplomatForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x005328f0
void TDiplomatForeignMinister::SetBuyPriorities() {
  preferredResourceSlots40[0] = 2;
  if (HasAdvancedTradeResource(this)) {
    preferredResourceSlots40[3] = rand() % 2 == 0 ? 1 : 0;
    if (ownerContextAt04->GetStockpile(kResourceIron) <
        ownerContextAt04->GetStockpile(kResourceCoal)) {
      preferredResourceSlots40[1] = 4;
      preferredResourceSlots40[2] = ownerContextAt04->GetStockpile(kResourceOil) <
                                            ownerContextAt04->GetStockpile(kResourceCoal)
                                        ? 6
                                        : 3;
    } else {
      preferredResourceSlots40[1] = 3;
      preferredResourceSlots40[2] = ownerContextAt04->GetStockpile(kResourceOil) <
                                            ownerContextAt04->GetStockpile(kResourceIron)
                                        ? 6
                                        : 4;
    }
    TForeignMinister::SetBuyPriorities();
    return;
  }

  bool hasTradeCandidate = false;
  for (short nationSlot = 7; nationSlot <= 0x16 && !hasTradeCandidate; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 &&
        (g_pNationInteractionStateManager->categoryRows[3].cells18[nationSlot + 0x2e] != 0 ||
         g_pNationInteractionStateManager->categoryRows[4].cells18[nationSlot + 0x2e] != 0)) {
      hasTradeCandidate = true;
    }
  }
  if (!hasTradeCandidate) {
    preferredResourceSlots40[1] = 0;
    preferredResourceSlots40[2] = 1;
    preferredResourceSlots40[3] = rand() < 0x3ffe ? 3 : 4;
  } else if (((g_pSimMgr->economicTurn / 4) & 1) != 0) {
    if (ownerContextAt04->GetStockpile(kResourceIron) <
        ownerContextAt04->GetStockpile(kResourceCoal)) {
      preferredResourceSlots40[1] = 4;
      preferredResourceSlots40[2] = 3;
    } else {
      preferredResourceSlots40[1] = 3;
      preferredResourceSlots40[2] = 4;
    }
    preferredResourceSlots40[3] =
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0) >
                g_pNationInteractionStateManager->QueryProposalWeightSlot4C(1)
            ? 0
            : 1;
  } else {
    if (ownerContextAt04->GetStockpile(kResourceCotton) <
        ownerContextAt04->GetStockpile(kResourceWool)) {
      preferredResourceSlots40[1] = 0;
      preferredResourceSlots40[2] = 1;
    } else {
      preferredResourceSlots40[1] = 1;
      preferredResourceSlots40[2] = 0;
    }
    preferredResourceSlots40[3] = ownerContextAt04->GetStockpile(kResourceIron) <
                                          ownerContextAt04->GetStockpile(kResourceCoal)
                                      ? 4
                                      : 3;
  }
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00532c60
void TDiplomatForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = ownerContextAt04;
  short targetAmount = owner->treasuryValue10 < 0 ? owner->merchantCapacity
                                                  : static_cast<short>(owner->merchantCapacity / 2);
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize14 = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short amounts[0x11] = {0};
  int selectedOrdinal = 3;
  int iteration = 0;
  while (targetAmount > 0 && iteration < targetAmount * 3) {
    short resourceCode = GetSortedResourceCode(prices, selectedOrdinal);
    if (amounts[resourceCode] < owner->GetStockpile(resourceCode)) {
      ++amounts[resourceCode];
      owner->SetItemPotentials(resourceCode, amounts[resourceCode]);
    }
    if (amounts[0x0d] + amounts[0x0e] + amounts[0x0f] >= targetAmount) {
      break;
    }
    --selectedOrdinal;
    if (selectedOrdinal == 0) {
      selectedOrdinal = 3;
    }
    ++iteration;
  }
  prices->ReleasePtrList();
  if (g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x10) > 1200 &&
      owner->GetStockpile(kResourceArms) > 6 &&
      g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(owner->nationSlot) == 0) {
    owner->SetItemPotentials(kResourceArms, 2);
  }
}

// FUNCTION: IMPERIALISM 0x00532f70
void TDiplomatForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                                 short resourceCode) {
  if (purchasePriorityByResource1e[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(arg1, arg2, arg3, resourceCode);
    return;
  }
  TGreatPower* owner = ownerContextAt04;
  short amount = owner->merchantCapacity < 12 ? 1 : (owner->merchantCapacity >= 25 ? 3 : 2);
  amount = MinShort(
      amount, static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode)));
  amount = MinShort(amount, arg2);
  g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3,
                                                   resourceCode, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00533050
void TDiplomatForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] += 5;
}

// ===================== TTextileForeignMinister (0x65a008) =====================

// SYNTHETIC: IMPERIALISM 0x00533070
// TTextileForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x005330f0
// TTextileForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTextileForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00533110
TTextileForeignMinister::TTextileForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533180
// TTextileForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005331d0
void TTextileForeignMinister::SetBuyPriorities() {
  preferredResourceSlots40[0] = 0;
  preferredResourceSlots40[1] = 1;
  TMinisterBaseOrderArray* priorities = new TMinisterBaseOrderArray();
  priorities->recordSize14 = sizeof(ResourcePriorityEntry);
  const short resources[4] = {3, 4, 2, 6};
  int resourceCount = HasAdvancedTradeResource(this) ? 4 : 3;
  for (int i = 0; i < resourceCount; ++i) {
    ResourcePriorityEntry entry;
    entry.resourceCode = resources[i];
    entry.priority = ownerContextAt04->GetStockpile(resources[i]);
    priorities->InsertCopiedRecordSortedByComparator(&entry);
  }
  for (int selectedIndex = 0; selectedIndex < 2; ++selectedIndex) {
    ResourcePriorityEntry* entry = static_cast<ResourcePriorityEntry*>(
        priorities->GetPtrListEntryByOneBasedIndex(selectedIndex + 1));
    preferredResourceSlots40[selectedIndex + 2] = entry->resourceCode;
  }
  priorities->ReleasePtrList();
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00533380
void TTextileForeignMinister::SetTradeBids() {
  short merchantCapacity = ownerContextAt04->merchantCapacity;
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = ownerContextAt04;
  short textileAmount = owner->GetStockpile(kResourceClothing);
  if (owner->treasuryValue10 < 0 || textileAmount >= merchantCapacity ||
      (textileAmount > 4 &&
       g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0d) > 1000)) {
    owner->SetItemPotentials(kResourceClothing, MinShort(textileAmount, merchantCapacity));
  }
  if (owner->treasuryValue10 < 0 || owner->GetTradeOffersFor(kResourceClothing) == 0) {
    short budget = static_cast<short>(merchantCapacity / 2);
    short firstResource = 0x0e;
    short secondResource = 0x0f;
    if (g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0f) >
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0e)) {
      firstResource = 0x0f;
      secondResource = 0x0e;
    }
    short firstAmount = MinShort(budget, owner->GetStockpile(firstResource));
    owner->SetItemPotentials(firstResource, firstAmount);
    short remaining = static_cast<short>(budget - firstAmount);
    owner->SetItemPotentials(secondResource,
                             MinShort(remaining, owner->GetStockpile(secondResource)));
  }
  SetTedStyleAdvancedResourceBid(this, 1500);
}

// FUNCTION: IMPERIALISM 0x00533670
void TTextileForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                                short resourceCode) {
  if (purchasePriorityByResource1e[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(arg1, arg2, arg3, resourceCode);
    return;
  }
  TGreatPower* owner = ownerContextAt04;
  short available =
      static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
  short amount =
      available >= arg2
          ? arg2
          : static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
  g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3,
                                                   resourceCode, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00533780
void TTextileForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] += 2;
  city->orderCountByType5c[1] += 1;
  short nextLevel = static_cast<short>(city->GetBuildingType(2) + 2);
  city->productionAccum1fc[2] = static_cast<short>(city->productionAccum1fc[2] + nextLevel -
                                                   city->productionOrderTable1dc[2]);
  city->productionOrderTable1dc[2] = nextLevel;
  nextLevel = static_cast<short>(city->GetBuildingType(1) + 1);
  city->productionAccum1fc[1] = static_cast<short>(city->productionAccum1fc[1] + nextLevel -
                                                   city->productionOrderTable1dc[1]);
  city->productionOrderTable1dc[1] = nextLevel;
}

// ===================== TTraderForeignMinister (0x65a0c8) =====================

// SYNTHETIC: IMPERIALISM 0x00533800
// TTraderForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00533880
// TTraderForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTraderForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005338a0
TTraderForeignMinister::TTraderForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533910
// TTraderForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00533960
void TTraderForeignMinister::SetBuyPriorities() {
  TMinisterBaseOrderArray* priorities = new TMinisterBaseOrderArray();
  priorities->recordSize14 = sizeof(ResourcePriorityEntry);
  for (short resourceCode = 0; resourceCode <= kResourceIron; ++resourceCode) {
    ResourcePriorityEntry entry;
    entry.resourceCode = resourceCode;
    entry.priority = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceCode);
    if (resourceCode == kResourceCoal || resourceCode == kResourceIron) {
      entry.priority = static_cast<short>(entry.priority - 15);
    }
    priorities->InsertCopiedRecordSortedByComparator(&entry);
  }
  if (HasAdvancedTradeResource(this)) {
    ResourcePriorityEntry entry;
    entry.resourceCode = 6;
    entry.priority =
        static_cast<short>(g_pNationInteractionStateManager->QueryProposalWeightSlot4C(6) - 15);
    priorities->InsertCopiedRecordSortedByComparator(&entry);
  }
  for (int i = 0; i < 4; ++i) {
    ResourcePriorityEntry* entry =
        static_cast<ResourcePriorityEntry*>(priorities->GetPtrListEntryByOneBasedIndex(i + 1));
    preferredResourceSlots40[i] = entry->resourceCode;
  }
  priorities->ReleasePtrList();
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00533b10
void TTraderForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = ownerContextAt04;
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize14 = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short divisor = owner->treasuryValue10 < 0 ? 1 : 4;
  short budget = static_cast<short>(owner->merchantCapacity / divisor);
  int selectedOrdinal = 3;
  short allocated = 0;
  while (budget > allocated && selectedOrdinal >= 1) {
    short resourceCode = GetSortedResourceCode(prices, selectedOrdinal);
    short amount = owner->GetStockpile(resourceCode);
    owner->SetItemPotentials(resourceCode, amount);
    allocated = static_cast<short>(allocated + owner->GetStockpile(resourceCode));
    --selectedOrdinal;
  }
  prices->ReleasePtrList();
  if (g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x10) > 1200 &&
      owner->GetStockpile(kResourceArms) > 6 &&
      g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(owner->nationSlot) == 0) {
    owner->SetItemPotentials(kResourceArms, 2);
  }
}

// FUNCTION: IMPERIALISM 0x00533db0
void TTraderForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                               short resourceCode) {
  if (purchasePriorityByResource1e[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(arg1, arg2, arg3, resourceCode);
    return;
  }
  TGreatPower* owner = ownerContextAt04;
  short available =
      static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
  short amount =
      available >= arg2
          ? arg2
          : static_cast<short>(owner->GetAvailableMerchantCapacityForProposal(resourceCode));
  g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, amount, arg3,
                                                   resourceCode, available < arg2, 0);
}

// FUNCTION: IMPERIALISM 0x00533e90
void TTraderForeignMinister::DoFirstTurnDiplomacy() {
  short selectedNations[4] = {0, 0, 0, 0};
  short selectedCount = 0;
  short attempts = 0;
  while (selectedCount < 4) {
    if (attempts > 15) {
      return;
    }
    ++attempts;
    short candidate = static_cast<short>(abs(rand()) % 0x10 + 7);
    bool duplicate = false;
    for (int index = 0; index < selectedCount; ++index) {
      if (selectedNations[index] == candidate) {
        duplicate = true;
      }
    }
    if (!duplicate && g_apTerrainTypeDescriptorTable[candidate] != 0) {
      selectedNations[selectedCount] = candidate;
      ownerContextAt04->ApplyDiplomacyPolicyStateForTargetWithCostChecks(candidate, 0x133);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00533f50
void TTraderForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] += 3;
}

// ===================== TArmsForeignMinister (0x65a188) =====================

// SYNTHETIC: IMPERIALISM 0x00533f70
// TArmsForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00533ff0
// TArmsForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TArmsForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00534010
TArmsForeignMinister::TArmsForeignMinister() : TForeignMinister() {
  field48 = 1;
  tradeBidRefreshInterval1a = 4;
  interiorOrderKind1c = 1;
  skillIndexC = 0;
}

// SYNTHETIC: IMPERIALISM 0x00534080
// TArmsForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005340d0
void TArmsForeignMinister::SetBuyPriorities() {
  if (HasAdvancedTradeResource(this)) {
    preferredResourceSlots40[0] = 6;
    preferredResourceSlots40[1] = 2;
    preferredResourceSlots40[2] = 3;
    preferredResourceSlots40[3] = 4;
  } else {
    preferredResourceSlots40[0] = 2;
    preferredResourceSlots40[1] = 3;
    preferredResourceSlots40[2] = 4;
    preferredResourceSlots40[3] = rand() % 2;
  }
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00534190
void TArmsForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = ownerContextAt04;
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize14 = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short budget = static_cast<short>(owner->merchantCapacity / 2);
  int selectedOrdinal = 3;
  short allocated = 0;
  while (allocated < budget && selectedOrdinal >= 1) {
    short resourceCode = GetSortedResourceCode(prices, selectedOrdinal);
    short amount =
        MinShort(owner->GetStockpile(resourceCode), static_cast<short>(budget - allocated));
    owner->SetItemPotentials(resourceCode, amount);
    allocated = static_cast<short>(allocated + amount);
    --selectedOrdinal;
  }
  prices->ReleasePtrList();
  if (owner->treasuryValue10 < 0 &&
      g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(owner->nationSlot) == 0) {
    short available = owner->GetStockpile(kResourceArms);
    short amount = static_cast<short>(available / 10);
    if (amount > 10) {
      amount = 10;
    }
    if (amount > 2) {
      owner->SetItemPotentials(kResourceArms, amount);
    } else if (available > 6) {
      owner->SetItemPotentials(kResourceArms, 2);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00534450
void TArmsForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                             short resourceCode) {
  if (purchasePriorityByResource1e[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(arg1, arg2, arg3, resourceCode);
    return;
  }
  TGreatPower* owner = ownerContextAt04;
  bool eligibleForSplit;
  short* splitCount;
  if (HasAdvancedTradeResource(this)) {
    eligibleForSplit = resourceCode == kResourceTimber || resourceCode == kResourceCoal ||
                       resourceCode == kResourceIron;
    splitCount = &g_nArmsAdvancedResourceOfferSplitCount_006a3a58;
  } else {
    eligibleForSplit = resourceCode >= kResourceCotton && resourceCode <= kResourceCoal;
    splitCount = &g_nArmsBasicResourceOfferSplitCount_006a3a54;
  }
  if (eligibleForSplit) {
    if (tradePartnerEnabled49[resourceCode] != 0) {
      short divisor = *splitCount == 0 ? 3 : 2;
      capabilityFlag16 = static_cast<short>(owner->GetAvailableMerchantCapacity() / divisor);
      ++*splitCount;
    }
    tradePartnerEnabled49[resourceCode] = 0;
  } else {
    capabilityFlag16 = owner->GetAvailableMerchantCapacity();
  }
  if (capabilityFlag16 >= arg2) {
    g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, arg2, arg3,
                                                     resourceCode, 0, 0);
    capabilityFlag16 = static_cast<short>(capabilityFlag16 - arg2);
  } else {
    g_pNationInteractionStateManager->SetDealResults(owner->nationSlot, arg1, capabilityFlag16,
                                                     arg3, resourceCode, 1, 0);
    capabilityFlag16 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00534660
void TArmsForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] += 5;
}
