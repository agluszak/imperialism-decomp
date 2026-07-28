#include "game/city/TShipOrder.h"

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"

static __inline short ReadWeight(const short* tableBase, short index) {
  return tableBase[static_cast<unsigned int>(index)];
}

enum {
  kResourceWeightIndex03 = 3,
  kResourceWeightIndex08 = 8,
  kResourceWeightIndex09 = 9,
  kResourceWeightIndex0B = 11,
  kResourceWeightIndex0C = 12,
  kResourceWeightIndex10 = 16,
};

// SYNTHETIC: IMPERIALISM 0x004b8470
// TShipOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b84a0
// TShipOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b84e0
// TShipOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b8510
TShipOrder::~TShipOrder() {}

// FUNCTION: IMPERIALISM 0x004b85a0
bool TShipOrder::CanMakeFromCityStock() {
  TCity* city = this->ownerCity;

  if (ReadWeight(g_industryActionCostWeightResCode09, this->resourceTypeIndex) <=
          city->cityStockLumberC8 &&
      ReadWeight(g_industryActionCostWeightResCode08, this->resourceTypeIndex) <=
          city->cityStockFabricC6 &&
      ReadWeight(g_industryActionCostWeightResCode10, this->resourceTypeIndex) <=
          city->cityStockArmsD6 &&
      ReadWeight(g_industryActionCostWeightResCode0B, this->resourceTypeIndex) <=
          city->cityStockSteelCC &&
      ReadWeight(g_industryActionCostWeightResCode03, this->resourceTypeIndex) <=
          city->cityStockCoalBC &&
      ReadWeight(g_industryActionCostWeightResCode0C, this->resourceTypeIndex) <=
          city->cityStockFuelCE) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8630
bool TShipOrder::CanFillOrderSheet() {
  const short weightIndex = this->resourceTypeIndex;
  const short weight09 = ReadWeight(g_industryActionCostWeightResCode09, weightIndex);
  const short weight08 = ReadWeight(g_industryActionCostWeightResCode08, weightIndex);
  const short weight10 = ReadWeight(g_industryActionCostWeightResCode10, weightIndex);
  const short weight0B = ReadWeight(g_industryActionCostWeightResCode0B, weightIndex);
  const short weight03 = ReadWeight(g_industryActionCostWeightResCode03, weightIndex);
  const short weight0C = ReadWeight(g_industryActionCostWeightResCode0C, weightIndex);

  if (static_cast<int>(weight09) <=
          static_cast<int>(this->trackingSlots[kResourceWeightIndex09] + weight09) &&
      static_cast<int>(weight08) <=
          static_cast<int>(this->trackingSlots[kResourceWeightIndex08] + weight08) &&
      static_cast<int>(weight10) <=
          static_cast<int>(this->trackingSlots[kResourceWeightIndex10] + weight10) &&
      static_cast<int>(weight0B) <=
          static_cast<int>(this->trackingSlots[kResourceWeightIndex0B] + weight0B) &&
      static_cast<int>(weight03) <=
          static_cast<int>(this->trackingSlots[kResourceWeightIndex03] + weight03) &&
      static_cast<int>(weight0C) <=
          static_cast<int>(this->trackingSlots[kResourceWeightIndex0C] + weight0C)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b86d0
short TShipOrder::MaxOrder() {
  TCity* city = this->ownerCity;
  const short weightIndex = this->resourceTypeIndex;
  int limit = 10000;
  int candidate;

  if (ReadWeight(g_industryActionCostWeightResCode09, weightIndex) != 0) {
    candidate = static_cast<int>(city->cityStockLumberC8) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode09, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode08, weightIndex) != 0) {
    candidate = static_cast<int>(city->cityStockFabricC6) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode08, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode10, weightIndex) != 0) {
    candidate = static_cast<int>(city->cityStockArmsD6) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode10, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode03, weightIndex) != 0) {
    candidate = static_cast<int>(city->cityStockCoalBC) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode03, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode0B, weightIndex) != 0) {
    candidate = static_cast<int>(city->cityStockSteelCC) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode0B, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode0C, weightIndex) != 0) {
    candidate = static_cast<int>(city->cityStockFuelCE) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode0C, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  return static_cast<short>(this->quantity + static_cast<short>(limit));
}

// FUNCTION: IMPERIALISM 0x004b8800
bool TShipOrder::SetQuantity(short quantity) {
  TCity* city = this->ownerCity;
  const short priorQuantity = this->quantity;
  const short delta = quantity - priorQuantity;
  const short weightIndex = this->resourceTypeIndex;
  const short maxAllowed = static_cast<short>(this->MaxOrder());

  if (maxAllowed < quantity || quantity < 0) {
    return 0;
  }

  this->quantity = quantity;

  city->cityStockLumberC8 =
      static_cast<short>(city->cityStockLumberC8 -
                         ReadWeight(g_industryActionCostWeightResCode09, weightIndex) * delta);
  city->VerifyStocks();
  city->cityStockFabricC6 =
      static_cast<short>(city->cityStockFabricC6 -
                         ReadWeight(g_industryActionCostWeightResCode08, weightIndex) * delta);
  city->VerifyStocks();
  city->cityStockArmsD6 = static_cast<short>(
      city->cityStockArmsD6 - ReadWeight(g_industryActionCostWeightResCode10, weightIndex) * delta);
  city->VerifyStocks();
  city->cityStockSteelCC =
      static_cast<short>(city->cityStockSteelCC -
                         ReadWeight(g_industryActionCostWeightResCode0B, weightIndex) * delta);
  city->VerifyStocks();
  city->cityStockCoalBC = static_cast<short>(
      city->cityStockCoalBC - ReadWeight(g_industryActionCostWeightResCode03, weightIndex) * delta);
  city->VerifyStocks();
  city->cityStockFuelCE = static_cast<short>(
      city->cityStockFuelCE - ReadWeight(g_industryActionCostWeightResCode0C, weightIndex) * delta);
  city->VerifyStocks();
  return 1;
}

// FUNCTION: IMPERIALISM 0x004b8970
void TShipOrder::Produce() {
  if (this->resourceTypeIndex != 0 && this->quantity != 0) {
    this->CommitQueuedNavyOrdersAndUpdateTierByCapability();
  }
}

// FUNCTION: IMPERIALISM 0x004b89a0
void TShipOrder::CommitQueuedNavyOrdersAndUpdateTierByCapability() {
  short quantity = this->quantity;
  TCity* city = this->ownerCity;

  city->productionOrderTable1dc[this->resourceTypeIndex] =
      static_cast<short>(city->productionOrderTable1dc[this->resourceTypeIndex] + quantity);
  this->quantity = static_cast<short>(quantity - 1);

  while (quantity != 0) {
    const int nationSlot = static_cast<int>(city->ownerNationAc->nationSlot);
    TZone* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(city);
    CreateNavyPrimaryOrderNodeAndAssignDisplayName(this->resourceTypeIndex, portZone, nationSlot,
                                                   0);
    quantity = this->quantity;
    this->quantity = static_cast<short>(quantity - 1);
  }

  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    this->trackingSlots[resource] = 0;
  }
  this->quantity = 0;

  TGreatPower* owner = city->ownerNationAc;
  if (owner->pendingActionStatus.roles.navyOrderStatus00 == '2') {
    return;
  }

  short currentCapability = owner->GetBuildingCapacity(2);
  short desiredCapability;
  if (owner->pendingActionStatus.roles.navyOrderStatus00 == '\0') {
    desiredCapability = 0;
  } else {
    desiredCapability =
        static_cast<short>(owner->pendingActionStatus.roles.navyOrderStatus00 - 0x33);
  }

  if (currentCapability < 0x19) {
    if (0x31 < currentCapability) {
      goto tier_two;
    }
    if (99 < currentCapability) {
      goto tier_three;
    }
    if (199 < currentCapability) {
      goto tier_four;
    }
    if (currentCapability < 300) {
      if (currentCapability < 400) {
        return;
      }
      goto tier_six;
    }
  } else {
    if (currentCapability < 0x32) {
      if (desiredCapability != 0) {
        return;
      }
      owner->SetNationPendingActionStateAndPayload(0, 1);
      return;
    }
  tier_two:
    if (currentCapability < 100) {
      if (1 < desiredCapability) {
        return;
      }
      owner->SetNationPendingActionStateAndPayload(0, 2);
      return;
    }
  tier_three:
    if (currentCapability < 200) {
      if (2 < desiredCapability) {
        return;
      }
      owner->SetNationPendingActionStateAndPayload(0, 3);
      return;
    }
  tier_four:
    if (currentCapability < 300) {
      if (3 < desiredCapability) {
        return;
      }
      owner->SetNationPendingActionStateAndPayload(0, 4);
      return;
    }
  }
  if (currentCapability < 400) {
    if (4 < desiredCapability) {
      return;
    }
    owner->SetNationPendingActionStateAndPayload(0, 5);
    return;
  }
tier_six:
  if (currentCapability < 500 && desiredCapability < 6) {
    owner->SetNationPendingActionStateAndPayload(0, 6);
  }
}

// FUNCTION: IMPERIALISM 0x004b8b80
void TShipOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  short value;

  this->ResetOrderSheet(orderSheet);

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode09, this->resourceTypeIndex) * quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex09] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex09] = 0;
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode08, this->resourceTypeIndex) * quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex08] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex08] = 0;
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode10, this->resourceTypeIndex) * quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex10] = value;
  // Matches the original: this clamp re-checks index 09, not the index 10 just written.
  if (orderSheet->slotByResourceCode[kResourceWeightIndex09] < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex09] = 0;
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode0B, this->resourceTypeIndex) * quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex0B] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex0B] = 0;
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode03, this->resourceTypeIndex) * quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex03] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex03] = 0;
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode0C, this->resourceTypeIndex) * quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex0C] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex0C] = 0;
  }
}
