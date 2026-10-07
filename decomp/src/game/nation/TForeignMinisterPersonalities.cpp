#include "game/nation/TForeignMinisterPersonalities.h"
#include "game/resource_domain_types.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/map/TSortByPriceList.h"
#include "game/core/TStream.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

namespace {

struct ResourcePriorityEntry {
  short resourceCode;
  short priority;
};

static bool HasAdvancedTradeResource(const TForeignMinister* minister) {
  return g_pTechMgr->orderCapRows277[minister->greatPower->nationSlot].techStatusByTechId[19] == 2;
}

static inline short MinShort(short a, short b) {
  return a < b ? a : b;
}

static inline void PreparePersonalityTradeBids(TForeignMinister* minister) {
  minister->InitializeTradeStatus();
  TGreatPower* owner = minister->greatPower;
  if (minister->diplomacyPhaseCounter >= minister->tradeBidRefreshInterval ||
      minister->WeNeedMoney() != 0) {
    owner->interiorMinister->PleaseBuildShip(minister->interiorOrderKind);
    minister->diplomacyPhaseCounter = 0;
  }
  minister->SetBuyPriorities();
  if (minister->interiorBidResource != -10) {
    short resourceCode = minister->interiorBidResource;
    owner->SetItemPotentials(resourceCode, -1);
    minister->purchasePriorityByResource[resourceCode] = minister->interiorBidAmount;
  }
  for (int index = 0; index < 4; ++index) {
    owner->SetItemPotentials(minister->preferredResourceSlots[index], -1);
  }
}

static inline void AddSortedResourcePrice(TSortByPriceList* prices, short resourceCode) {
  ResourcePriorityEntry entry;
  entry.resourceCode = resourceCode;
  entry.priority = g_pTradeMgr->GetPrice(resourceCode);
  prices->Insert(&entry);
}

static inline short GetSortedResourceCode(TSortByPriceList* prices, int oneBasedIndex) {
  ResourcePriorityEntry* entry =
      static_cast<ResourcePriorityEntry*>(prices->GetPtrListEntryByOneBasedIndex(oneBasedIndex));
  return entry->resourceCode;
}

static inline void SetTedStyleAdvancedResourceBid(TForeignMinister* minister, short threshold) {
  TGreatPower* owner = minister->greatPower;
  if (g_pTradeMgr->GetPrice(0x10) > threshold &&
      !g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(owner->nationSlot)) {
    short available = owner->GetStockpile(kResourceArms);
    short amount = available / 10;
    if (amount > 2) {
      owner->SetItemPotentials(kResourceArms, amount);
    } else if (owner->GetStockpile(kResourceArms) > 6) {
      owner->SetItemPotentials(kResourceArms, 2);
    }
  }
}

} // namespace

// TTedForeignMinister

IMPLEMENT_DYNCREATE(TTedForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005311d0
TTedForeignMinister::TTedForeignMinister() : TForeignMinister() {
  tradeBidRefreshInterval = 4;
  this->skillIndex = 5;
}

// FUNCTION: IMPERIALISM 0x00531290
void TTedForeignMinister::SetBuyPriorities() {
  if (!HasAdvancedTradeResource(this)) {
    if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
      preferredResourceSlots[0] = 4;
      preferredResourceSlots[2] = 3;
    } else {
      preferredResourceSlots[0] = 3;
      preferredResourceSlots[2] = 4;
    }
    preferredResourceSlots[1] = 2;
    if (rand() < 0x3ffe) {
      preferredResourceSlots[3] = 0;
    } else {
      preferredResourceSlots[3] = 1;
    }
    TForeignMinister::SetBuyPriorities();
    return;
  }

  if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
    preferredResourceSlots[0] = kResourceIron;
    if (greatPower->GetStockpile(kResourceOil) < greatPower->GetStockpile(kResourceCoal)) {
      preferredResourceSlots[1] = kResourceOil;
      if (greatPower->GetStockpile(kResourceTimber) < greatPower->GetStockpile(kResourceCoal)) {
        preferredResourceSlots[2] = kResourceTimber;
      } else {
        preferredResourceSlots[2] = kResourceCoal;
      }
    } else {
      preferredResourceSlots[1] = kResourceCoal;
      if (greatPower->GetStockpile(kResourceOil) > greatPower->GetStockpile(kResourceTimber)) {
        preferredResourceSlots[2] = kResourceTimber;
      } else {
        preferredResourceSlots[2] = kResourceOil;
      }
    }
  } else {
    preferredResourceSlots[0] = kResourceCoal;
    if (greatPower->GetStockpile(kResourceOil) < greatPower->GetStockpile(kResourceIron)) {
      preferredResourceSlots[1] = kResourceOil;
      if (greatPower->GetStockpile(kResourceIron) > greatPower->GetStockpile(kResourceTimber)) {
        preferredResourceSlots[2] = kResourceTimber;
      } else {
        preferredResourceSlots[2] = kResourceIron;
      }
    } else {
      preferredResourceSlots[1] = kResourceIron;
      if (greatPower->GetStockpile(kResourceOil) > greatPower->GetStockpile(kResourceTimber)) {
        preferredResourceSlots[2] = kResourceTimber;
      } else {
        preferredResourceSlots[2] = kResourceOil;
      }
    }
  }
  if (rand() < 0x3ffe) {
    preferredResourceSlots[3] = 0;
    TForeignMinister::SetBuyPriorities();
    return;
  }
  preferredResourceSlots[3] = 1;
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00531550
void TTedForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = greatPower;
  short merchantCapacity = owner->merchantCapacity;
  short resourceAmount = owner->GetStockpile(kResourceHardware);
  if (owner->treasuryValue >= 0 && merchantCapacity > resourceAmount && resourceAmount < 10) {
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
void TTedForeignMinister::ReplyToTradeOffer(short targetNation, short requestedAmount,
                                            short maximumAmount, short resourceCode) {
  if (purchasePriorityByResource[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(targetNation, requestedAmount, maximumAmount, resourceCode);
    return;
  }
  TGreatPower* owner = greatPower;
  if (resourceCode == kResourceCoal) {
    if (tradePartnerEnabled[3] != 0) {
      specialOfferQuota = static_cast<short>(owner->GetUnreservedMerchantCapacity(3) / 2);
      tradePartnerEnabled[3] = 0;
    }
    if (specialOfferQuota >= requestedAmount) {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                  3, 0, false);
      specialOfferQuota = static_cast<short>(specialOfferQuota - requestedAmount);
    } else {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, specialOfferQuota, maximumAmount,
                                  3, 1, false);
      specialOfferQuota = 0;
    }
    return;
  }
  if (resourceCode == kResourceTimber || resourceCode == kResourceIron ||
      resourceCode == kResourceOil) {
    short available = owner->GetUnreservedMerchantCapacity(resourceCode);
    if (available >= requestedAmount) {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                  resourceCode, 0, false);
    } else {
      g_pTradeMgr->SetDealResults(
          owner->nationSlot, targetNation,
          static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)), maximumAmount,
          resourceCode, 0, false);
    }
    return;
  }
  if (resourceCode == kResourceCotton || resourceCode == kResourceWool) {
    short amount = owner->merchantCapacity < 15 ? 1 : (owner->merchantCapacity >= 30 ? 3 : 2);
    amount = MinShort(amount, requestedAmount);
    if (static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)) >= amount) {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, amount, maximumAmount,
                                  resourceCode, 0, false);
    } else {
      g_pTradeMgr->SetDealResults(
          owner->nationSlot, targetNation,
          static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)), maximumAmount,
          resourceCode, 0, false);
    }
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
    short candidate = abs(rand()) % 16 + 7;
    bool duplicate = false;
    for (int index = 0; index < selectedCount; ++index) {
      if (selectedNations[index] == candidate) {
        duplicate = true;
      }
    }
    if (!duplicate && !g_pGlobalMapState->IsSameContinent(greatPower->nationSlot, candidate) &&
        g_apTerrainTypeDescriptorTable[candidate] != 0) {
      selectedNations[selectedCount] = candidate;
      greatPower->SetDiplomacyPolicyTo(candidate, 0x133);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00531af0
void TTedForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x00531b10
void TTedForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType[2] = 3;
}

// TBillForeignMinister

IMPLEMENT_DYNCREATE(TBillForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00531be0
TBillForeignMinister::TBillForeignMinister() : TForeignMinister() {
  orderFlag = 0;
  field48 = 1;
  interiorOrderKind = 1;
  tradeBidRefreshInterval = 4;
  skillIndex = 4;
}

// FUNCTION: IMPERIALISM 0x00531ca0
void TBillForeignMinister::ReadFrom(TStream* stream) {
  TForeignMinister::ReadFrom(stream);
  stream->ReadBytes(&orderFlag, 1);
}

// FUNCTION: IMPERIALISM 0x00531ce0
void TBillForeignMinister::WriteTo(TStream* stream) {
  TForeignMinister::WriteTo(stream);
  stream->WriteBytes(&orderFlag, 1);
}

// FUNCTION: IMPERIALISM 0x00531d20
void TBillForeignMinister::SetBuyPriorities() {
  if (HasAdvancedTradeResource(this)) {
    if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
      preferredResourceSlots[0] = 4;
      preferredResourceSlots[3] = 3;
    } else {
      preferredResourceSlots[0] = 3;
      preferredResourceSlots[3] = 4;
    }
    preferredResourceSlots[1] = 2;
    preferredResourceSlots[2] = 6;
    TForeignMinister::SetBuyPriorities();
    return;
  }

  if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
    preferredResourceSlots[0] = 4;
    preferredResourceSlots[2] = 3;
  } else {
    preferredResourceSlots[0] = 3;
    preferredResourceSlots[2] = 4;
  }
  preferredResourceSlots[1] = 2;
  preferredResourceSlots[3] = -10;
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00531e50
void TBillForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = greatPower;
  short targetAmount = owner->treasuryValue < 0 ? owner->merchantCapacity
                                                : static_cast<short>(owner->merchantCapacity / 2);
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short amounts[17] = {0};
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
  prices->FreeList();
  SetTedStyleAdvancedResourceBid(this, 1500);
}

// FUNCTION: IMPERIALISM 0x00532190
void TBillForeignMinister::ReplyToTradeOffer(short targetNation, short requestedAmount,
                                             short maximumAmount, short resourceCode) {
  if (purchasePriorityByResource[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(targetNation, requestedAmount, maximumAmount, resourceCode);
    return;
  }
  TGreatPower* owner = greatPower;
  short available;
  short amount;
  if (resourceCode == kResourceTimber) {
    if (g_pTradeMgr->GetPrice(3) >= 105 && g_pTradeMgr->GetPrice(4) >= 105) {
      if (tradePartnerEnabled[2] != 0) {
        specialOfferQuota = static_cast<short>(owner->GetMerchantCapacity() / 3);
        if (specialOfferQuota < 2) {
          specialOfferQuota = 2;
        }
        tradePartnerEnabled[2] = 0;
      }
      available = owner->GetMerchantCapacity();
      amount = MinShort(specialOfferQuota, available);
      if (amount >= requestedAmount) {
        g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                    2, 0, false);
        specialOfferQuota = static_cast<short>(specialOfferQuota - requestedAmount);
        if (specialOfferQuota < 0) {
          specialOfferQuota = 0;
        }
      } else {
        g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, amount, maximumAmount, 2, 1,
                                    false);
        specialOfferQuota = 0;
      }
    } else {
      available = owner->GetMerchantCapacity();
      amount = available >= requestedAmount ? requestedAmount : owner->GetMerchantCapacity();
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, amount, maximumAmount, 2, 0,
                                  false);
    }
    return;
  }
  if (resourceCode == kResourceCoal) {
    if (tradePartnerEnabled[3] != 0) {
      specialOfferQuota = static_cast<short>(owner->GetMerchantCapacity() / 2);
      tradePartnerEnabled[3] = 0;
    }
    amount = g_pTradeMgr->GetPrice(4) < 105 ? requestedAmount : specialOfferQuota;
    amount = MinShort(amount, requestedAmount);
    available = owner->GetMerchantCapacity();
    if (available >= amount) {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, amount, maximumAmount, 3, 0,
                                  false);
      specialOfferQuota = static_cast<short>(specialOfferQuota - amount);
    } else {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, owner->GetMerchantCapacity(),
                                  maximumAmount, 3, 0, false);
      specialOfferQuota = 0;
    }
    return;
  }
  if (resourceCode == kResourceIron || resourceCode == kResourceOil) {
    available = owner->GetMerchantCapacity();
    if (available >= requestedAmount) {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                  resourceCode, 0, false);
      if (resourceCode == kResourceIron) {
        specialOfferQuota = static_cast<short>(specialOfferQuota - requestedAmount);
      }
    } else {
      g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, owner->GetMerchantCapacity(),
                                  maximumAmount, resourceCode, resourceCode == kResourceIron,
                                  false);
      if (resourceCode == kResourceIron) {
        specialOfferQuota = 0;
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
    short candidate = abs(rand()) % 16 + 7;
    if ((selectedCount == 0 || selectedNations[0] != candidate) &&
        !g_pGlobalMapState->IsSameContinent(greatPower->nationSlot, candidate) &&
        g_apTerrainTypeDescriptorTable[candidate] != 0) {
      selectedNations[selectedCount] = candidate;
      greatPower->SetDiplomacyPolicyTo(candidate, 0x133);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005325e0
void TBillForeignMinister::DoSecondTurnDiplomacy() {
  short selectedCount = 0;
  for (short candidate = 7; candidate < 23 && selectedCount < 2; ++candidate) {
    if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(greatPower->nationSlot, candidate) >= 1) {
      greatPower->SetTradePolicyTo(static_cast<NationSlot>(candidate), 0x5a);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00532650
void TBillForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType[1] = 3;
  short nextLevel = city->GetBuildingType(2) + 2;
  city->productionAccum[2] =
      static_cast<short>(city->productionAccum[2] + nextLevel - city->productionOrderTable[2]);
  city->productionOrderTable[2] = nextLevel;
  nextLevel = static_cast<short>(city->GetBuildingType(4) + 2);
  city->productionAccum[4] =
      static_cast<short>(city->productionAccum[4] + nextLevel - city->productionOrderTable[4]);
  city->productionOrderTable[4] = nextLevel;
  city->SetRollingStock(static_cast<short>(city->GetRollingStock() + 2));
}

// TDiplomatForeignMinister

IMPLEMENT_DYNCREATE(TDiplomatForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00532780
TDiplomatForeignMinister::TDiplomatForeignMinister() : TForeignMinister() {
  skillIndex = 3;
}

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
    greatPower->SetDiplomacyPolicyTo(nation, 0x133);
  }
}

// FUNCTION: IMPERIALISM 0x005328d0
void TDiplomatForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x005328f0
void TDiplomatForeignMinister::SetBuyPriorities() {
  preferredResourceSlots[0] = 2;
  if (HasAdvancedTradeResource(this)) {
    preferredResourceSlots[3] = rand() % 2 == 0 ? 1 : 0;
    if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
      preferredResourceSlots[1] = 4;
      if (greatPower->GetStockpile(kResourceOil) < greatPower->GetStockpile(kResourceCoal)) {
        preferredResourceSlots[2] = 6;
        TForeignMinister::SetBuyPriorities();
        return;
      }
      preferredResourceSlots[2] = 3;
      TForeignMinister::SetBuyPriorities();
      return;
    } else {
      preferredResourceSlots[1] = 3;
      if (greatPower->GetStockpile(kResourceOil) < greatPower->GetStockpile(kResourceIron)) {
        preferredResourceSlots[2] = 6;
        TForeignMinister::SetBuyPriorities();
        return;
      }
      preferredResourceSlots[2] = 4;
      TForeignMinister::SetBuyPriorities();
      return;
    }
  }

  bool hasTradeCandidate = false;
  for (short nationSlot = 7; nationSlot <= 22 && !hasTradeCandidate; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 &&
        (g_pTradeMgr->categoryRows[3].tradeOfferCells[nationSlot + 0x2e] != 0 ||
         g_pTradeMgr->categoryRows[4].tradeOfferCells[nationSlot + 0x2e] != 0)) {
      hasTradeCandidate = true;
    }
  }
  if (!hasTradeCandidate) {
    preferredResourceSlots[1] = 0;
    preferredResourceSlots[2] = 1;
    if (rand() < 0x3ffe) {
      preferredResourceSlots[3] = 3;
      TForeignMinister::SetBuyPriorities();
      return;
    }
    preferredResourceSlots[3] = 4;
    TForeignMinister::SetBuyPriorities();
    return;
  } else if (((g_pSimMgr->economicTurn / 4) & 1) != 0) {
    if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
      preferredResourceSlots[1] = 4;
      preferredResourceSlots[2] = 3;
    } else {
      preferredResourceSlots[1] = 3;
      preferredResourceSlots[2] = 4;
    }
    if (g_pTradeMgr->GetPrice(0) > g_pTradeMgr->GetPrice(1)) {
      preferredResourceSlots[3] = 0;
      TForeignMinister::SetBuyPriorities();
      return;
    }
    preferredResourceSlots[3] = 1;
    TForeignMinister::SetBuyPriorities();
    return;
  } else {
    if (greatPower->GetStockpile(kResourceCotton) < greatPower->GetStockpile(kResourceWool)) {
      preferredResourceSlots[1] = 0;
      preferredResourceSlots[2] = 1;
    } else {
      preferredResourceSlots[1] = 1;
      preferredResourceSlots[2] = 0;
    }
    if (greatPower->GetStockpile(kResourceIron) < greatPower->GetStockpile(kResourceCoal)) {
      preferredResourceSlots[3] = 4;
      TForeignMinister::SetBuyPriorities();
      return;
    }
    preferredResourceSlots[3] = 3;
    TForeignMinister::SetBuyPriorities();
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00532c60
void TDiplomatForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = greatPower;
  short targetAmount = owner->treasuryValue < 0 ? owner->merchantCapacity
                                                : static_cast<short>(owner->merchantCapacity / 2);
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short amounts[17] = {0};
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
  prices->FreeList();
  if (g_pTradeMgr->GetPrice(0x10) > 1200 && owner->GetStockpile(kResourceArms) > 6 &&
      !g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(owner->nationSlot)) {
    owner->SetItemPotentials(kResourceArms, 2);
  }
}

// FUNCTION: IMPERIALISM 0x00532f70
void TDiplomatForeignMinister::ReplyToTradeOffer(short targetNation, short requestedAmount,
                                                 short maximumAmount, short resourceCode) {
  if (purchasePriorityByResource[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(targetNation, requestedAmount, maximumAmount, resourceCode);
    return;
  }
  TGreatPower* owner = greatPower;
  short amount = owner->merchantCapacity < 12 ? 1 : (owner->merchantCapacity >= 25 ? 3 : 2);
  if (static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)) < amount) {
    amount = static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode));
  }
  amount = MinShort(amount, requestedAmount);
  g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, amount, maximumAmount, resourceCode,
                              0, false);
}

// FUNCTION: IMPERIALISM 0x00533050
void TDiplomatForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType[1] += 5;
}

// TTextileForeignMinister

IMPLEMENT_DYNCREATE(TTextileForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00533110
TTextileForeignMinister::TTextileForeignMinister() : TForeignMinister() {
  skillIndex = 2;
  field48 = 1;
}

// FUNCTION: IMPERIALISM 0x005331d0
void TTextileForeignMinister::SetBuyPriorities() {
  preferredResourceSlots[0] = 0;
  preferredResourceSlots[1] = 1;
  TSortByPriceList* priorities = new TSortByPriceList();
  priorities->recordSize = sizeof(ResourcePriorityEntry);
  ResourcePriorityEntry entry;
  entry.resourceCode = 3;
  entry.priority = greatPower->GetStockpile(3);
  priorities->Insert(&entry);
  entry.resourceCode = 4;
  entry.priority = greatPower->GetStockpile(4);
  priorities->Insert(&entry);
  entry.resourceCode = 2;
  entry.priority = greatPower->GetStockpile(2);
  priorities->Insert(&entry);
  if (HasAdvancedTradeResource(this)) {
    entry.resourceCode = 6;
    entry.priority = greatPower->GetStockpile(6);
    priorities->Insert(&entry);
  }
  ResourcePriorityEntry* first =
      static_cast<ResourcePriorityEntry*>(priorities->GetPtrListEntryByOneBasedIndex(1));
  preferredResourceSlots[2] = first->resourceCode;
  ResourcePriorityEntry* second =
      static_cast<ResourcePriorityEntry*>(priorities->GetPtrListEntryByOneBasedIndex(2));
  preferredResourceSlots[3] = second->resourceCode;
  priorities->FreeList();
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00533380
void TTextileForeignMinister::SetTradeBids() {
  short merchantCapacity = greatPower->merchantCapacity;
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = greatPower;
  if (owner->treasuryValue < 0 || owner->GetStockpile(kResourceClothing) >= merchantCapacity ||
      (owner->GetStockpile(kResourceClothing) > 4 && g_pTradeMgr->GetPrice(0x0d) > 1000)) {
    short textileAmount = owner->GetStockpile(kResourceClothing) < merchantCapacity
                              ? owner->GetStockpile(kResourceClothing)
                              : merchantCapacity;
    owner->SetItemPotentials(kResourceClothing, textileAmount);
  }
  if (owner->treasuryValue < 0 || owner->GetTradeOffersFor(kResourceClothing) == 0) {
    short budget = merchantCapacity / 2;
    short firstResource = 0x0e;
    short secondResource = 0x0f;
    if (g_pTradeMgr->GetPrice(0x0f) > g_pTradeMgr->GetPrice(0x0e)) {
      firstResource = 0x0f;
      secondResource = 0x0e;
    }
    short firstAmount =
        owner->GetStockpile(firstResource) <= budget ? owner->GetStockpile(firstResource) : budget;
    owner->SetItemPotentials(firstResource, firstAmount);
    short remaining = budget - firstAmount;
    short secondAmount = owner->GetStockpile(secondResource) < remaining
                             ? owner->GetStockpile(secondResource)
                             : remaining;
    owner->SetItemPotentials(secondResource, secondAmount);
  }
  SetTedStyleAdvancedResourceBid(this, 1500);
}

// FUNCTION: IMPERIALISM 0x00533670
void TTextileForeignMinister::ReplyToTradeOffer(short targetNation, short requestedAmount,
                                                short maximumAmount, short resourceCode) {
  if (purchasePriorityByResource[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(targetNation, requestedAmount, maximumAmount, resourceCode);
    return;
  }
  TGreatPower* owner = greatPower;
  if (static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)) >= requestedAmount) {
    g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                resourceCode, 0, false);
    return;
  }
  g_pTradeMgr->SetDealResults(
      owner->nationSlot, targetNation,
      static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)), maximumAmount,
      resourceCode, 0, false);
}

// FUNCTION: IMPERIALISM 0x00533780
void TTextileForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType[2] += 2;
  city->orderCountByType[1] += 1;
  short nextLevel = city->GetBuildingType(2) + 2;
  city->productionAccum[2] =
      static_cast<short>(city->productionAccum[2] + nextLevel - city->productionOrderTable[2]);
  city->productionOrderTable[2] = nextLevel;
  nextLevel = static_cast<short>(city->GetBuildingType(1) + 1);
  city->productionAccum[1] =
      static_cast<short>(city->productionAccum[1] + nextLevel - city->productionOrderTable[1]);
  city->productionOrderTable[1] = nextLevel;
}

// TTraderForeignMinister

IMPLEMENT_DYNCREATE(TTraderForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005338a0
TTraderForeignMinister::TTraderForeignMinister() : TForeignMinister() {
  skillIndex = 1;
}

// FUNCTION: IMPERIALISM 0x00533960
void TTraderForeignMinister::SetBuyPriorities() {
  TSortByPriceList* priorities = new TSortByPriceList();
  priorities->recordSize = sizeof(ResourcePriorityEntry);
  for (short resourceCode = 0; resourceCode <= kResourceIron; ++resourceCode) {
    ResourcePriorityEntry entry;
    entry.resourceCode = resourceCode;
    if (resourceCode == kResourceCoal || resourceCode == kResourceIron) {
      entry.priority = static_cast<short>(g_pTradeMgr->GetPrice(resourceCode) - 15);
    } else {
      entry.priority = g_pTradeMgr->GetPrice(resourceCode);
    }
    priorities->Insert(&entry);
  }
  if (HasAdvancedTradeResource(this)) {
    ResourcePriorityEntry entry;
    entry.resourceCode = 6;
    entry.priority = static_cast<short>(g_pTradeMgr->GetPrice(6) - 15);
    priorities->Insert(&entry);
  }
  for (int i = 0; i < 4; ++i) {
    ResourcePriorityEntry* entry =
        static_cast<ResourcePriorityEntry*>(priorities->GetPtrListEntryByOneBasedIndex(i + 1));
    preferredResourceSlots[i] = entry->resourceCode;
  }
  priorities->FreeList();
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00533b10
void TTraderForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = greatPower;
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short divisor = owner->treasuryValue < 0 ? 1 : 4;
  short budget = owner->merchantCapacity / divisor;
  int selectedOrdinal = 3;
  short allocated = 0;
  while (budget > allocated && selectedOrdinal >= 1) {
    short resourceCode = GetSortedResourceCode(prices, selectedOrdinal);
    short amount = owner->GetStockpile(resourceCode);
    owner->SetItemPotentials(resourceCode, amount);
    allocated += owner->GetStockpile(resourceCode);
    --selectedOrdinal;
  }
  prices->FreeList();
  if (g_pTradeMgr->GetPrice(0x10) > 1200 && owner->GetStockpile(kResourceArms) > 6 &&
      !g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(owner->nationSlot)) {
    owner->SetItemPotentials(kResourceArms, 2);
  }
}

// FUNCTION: IMPERIALISM 0x00533db0
void TTraderForeignMinister::ReplyToTradeOffer(short targetNation, short requestedAmount,
                                               short maximumAmount, short resourceCode) {
  if (purchasePriorityByResource[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(targetNation, requestedAmount, maximumAmount, resourceCode);
    return;
  }
  TGreatPower* owner = greatPower;
  short available = owner->GetUnreservedMerchantCapacity(resourceCode);
  if (available >= requestedAmount) {
    g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                resourceCode, 0, false);
  } else {
    g_pTradeMgr->SetDealResults(
        owner->nationSlot, targetNation,
        static_cast<short>(owner->GetUnreservedMerchantCapacity(resourceCode)), maximumAmount,
        resourceCode, 1, false);
  }
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
    short candidate = abs(rand()) % 16 + 7;
    bool duplicate = false;
    for (int index = 0; index < selectedCount; ++index) {
      if (selectedNations[index] == candidate) {
        duplicate = true;
      }
    }
    if (!duplicate && g_apTerrainTypeDescriptorTable[candidate] != 0) {
      selectedNations[selectedCount] = candidate;
      greatPower->SetDiplomacyPolicyTo(candidate, 0x133);
      ++selectedCount;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00533f50
void TTraderForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType[2] += 3;
}

// TArmsForeignMinister

IMPLEMENT_DYNCREATE(TArmsForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00534010
TArmsForeignMinister::TArmsForeignMinister() : TForeignMinister() {
  field48 = 1;
  tradeBidRefreshInterval = 4;
  interiorOrderKind = 1;
  skillIndex = 0;
}

// FUNCTION: IMPERIALISM 0x005340d0
void TArmsForeignMinister::SetBuyPriorities() {
  if (HasAdvancedTradeResource(this)) {
    preferredResourceSlots[0] = 6;
    preferredResourceSlots[1] = 2;
    preferredResourceSlots[2] = 3;
    preferredResourceSlots[3] = 4;
    TForeignMinister::SetBuyPriorities();
  } else {
    preferredResourceSlots[0] = 2;
    preferredResourceSlots[1] = 3;
    preferredResourceSlots[2] = 4;
    if (rand() % 2 != 0) {
      preferredResourceSlots[3] = 0;
      TForeignMinister::SetBuyPriorities();
      return;
    }
    preferredResourceSlots[3] = 1;
    TForeignMinister::SetBuyPriorities();
  }
}

// FUNCTION: IMPERIALISM 0x00534190
void TArmsForeignMinister::SetTradeBids() {
  PreparePersonalityTradeBids(this);
  TGreatPower* owner = greatPower;
  TSortByPriceList* prices = new TSortByPriceList();
  prices->recordSize = sizeof(ResourcePriorityEntry);
  AddSortedResourcePrice(prices, 0x0d);
  AddSortedResourcePrice(prices, 0x0e);
  AddSortedResourcePrice(prices, 0x0f);
  short budget = owner->merchantCapacity / 2;
  int selectedOrdinal = 3;
  short allocated = 0;
  while (allocated < budget && selectedOrdinal >= 1) {
    short resourceCode = GetSortedResourceCode(prices, selectedOrdinal);
    short amount =
        MinShort(owner->GetStockpile(resourceCode), static_cast<short>(budget - allocated));
    owner->SetItemPotentials(resourceCode, amount);
    allocated += amount;
    --selectedOrdinal;
  }
  prices->FreeList();
  if (owner->treasuryValue < 0 &&
      !g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(owner->nationSlot)) {
    short available = owner->GetStockpile(kResourceArms);
    short amount = available / 10;
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
void TArmsForeignMinister::ReplyToTradeOffer(short targetNation, short requestedAmount,
                                             short maximumAmount, short resourceCode) {
  if (purchasePriorityByResource[resourceCode] != 0) {
    TForeignMinister::ReplyToTradeOffer(targetNation, requestedAmount, maximumAmount, resourceCode);
    return;
  }
  TGreatPower* owner = greatPower;
  if (HasAdvancedTradeResource(this)) {
    if (resourceCode != kResourceTimber && resourceCode != kResourceCoal &&
        resourceCode != kResourceIron) {
      specialOfferQuota = owner->GetMerchantCapacity();
    } else if (tradePartnerEnabled[resourceCode] != 0) {
      if (g_nArmsAdvancedResourceOfferSplitCount == 0) {
        specialOfferQuota = static_cast<short>(owner->GetMerchantCapacity() / 3);
      } else {
        specialOfferQuota = static_cast<short>(owner->GetMerchantCapacity() / 2);
      }
      ++g_nArmsAdvancedResourceOfferSplitCount;
    }
  } else {
    if (resourceCode != kResourceCotton && resourceCode != kResourceWool &&
        resourceCode != kResourceTimber && resourceCode != kResourceCoal) {
      specialOfferQuota = owner->GetMerchantCapacity();
    } else if (tradePartnerEnabled[resourceCode] != 0) {
      if (g_nArmsBasicResourceOfferSplitCount == 0) {
        specialOfferQuota = static_cast<short>(owner->GetMerchantCapacity() / 3);
        ++g_nArmsBasicResourceOfferSplitCount;
      } else {
        specialOfferQuota = static_cast<short>(owner->GetMerchantCapacity() / 2);
        ++g_nArmsBasicResourceOfferSplitCount;
      }
    }
  }
  tradePartnerEnabled[resourceCode] = 0;
  if (specialOfferQuota >= requestedAmount) {
    g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, requestedAmount, maximumAmount,
                                resourceCode, 0, false);
    specialOfferQuota = static_cast<short>(specialOfferQuota - requestedAmount);
  } else {
    g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, specialOfferQuota, maximumAmount,
                                resourceCode, 1, false);
    specialOfferQuota = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00534660
void TArmsForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType[1] += 5;
}
