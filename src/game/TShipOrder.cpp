#include "game/TShipOrder.h"
#include "game/order_weight_helpers.h"

#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

static void ZeroShipOrderTrackingSlots(TShipOrder* order) {
  int remaining;
  int* cursor = reinterpret_cast<int*>(order->trackingSlots10);

  remaining = 0xb;
  while (remaining != 0) {
    *cursor = 0;
    cursor = cursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(cursor) = 0;
}

TShipOrder::TShipOrder()
    : quantityField04(0), cityField08(0), summaryField0c(0), field3e(0), field40(0), field44(0),
      resourceTypeIndex48(0), field4a(0) {
  ZeroShipOrderTrackingSlots(this);
}
IMPLEMENT_DYNCREATE(TShipOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b84e0
// TShipOrder::`scalar deleting destructor'
TShipOrder::~TShipOrder() {}

// FUNCTION: IMPERIALISM 0x004b85a0
bool TShipOrder::CanMakeFromCityStock() {
  TCity* city = this->cityField08;

  if (ReadWeight(g_industryActionCostWeightResCode09, this->resourceTypeIndex48) <=
          city->cityStockLumberC8 &&
      ReadWeight(g_industryActionCostWeightResCode08, this->resourceTypeIndex48) <=
          city->cityStockFabricC6 &&
      ReadWeight(g_industryActionCostWeightResCode10, this->resourceTypeIndex48) <=
          city->cityStockArmsD6 &&
      ReadWeight(g_industryActionCostWeightResCode0B, this->resourceTypeIndex48) <=
          city->cityStockSteelCC &&
      ReadWeight(g_industryActionCostWeightResCode03, this->resourceTypeIndex48) <=
          city->cityStockCoalBC &&
      ReadWeight(g_industryActionCostWeightResCode0C, this->resourceTypeIndex48) <=
          city->cityStockFuelCE) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b8630
bool TShipOrder::CanFillOrderSheet() {
  const short weightIndex = this->resourceTypeIndex48;
  const short weight09 = ReadWeight(g_industryActionCostWeightResCode09, weightIndex);
  const short weight08 = ReadWeight(g_industryActionCostWeightResCode08, weightIndex);
  const short weight10 = ReadWeight(g_industryActionCostWeightResCode10, weightIndex);
  const short weight0B = ReadWeight(g_industryActionCostWeightResCode0B, weightIndex);
  const short weight03 = ReadWeight(g_industryActionCostWeightResCode03, weightIndex);
  const short weight0C = ReadWeight(g_industryActionCostWeightResCode0C, weightIndex);

  if (static_cast<int>(weight09) <=
          static_cast<int>(this->trackingSlots10[kResourceWeightIndex09] + weight09) &&
      static_cast<int>(weight08) <=
          static_cast<int>(this->trackingSlots10[kResourceWeightIndex08] + weight08) &&
      static_cast<int>(weight10) <=
          static_cast<int>(this->trackingSlots10[kResourceWeightIndex10] + weight10) &&
      static_cast<int>(weight0B) <=
          static_cast<int>(this->trackingSlots10[kResourceWeightIndex0B] + weight0B) &&
      static_cast<int>(weight03) <=
          static_cast<int>(this->trackingSlots10[kResourceWeightIndex03] + weight03) &&
      static_cast<int>(weight0C) <=
          static_cast<int>(this->trackingSlots10[kResourceWeightIndex0C] + weight0C)) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b86d0
short TShipOrder::MaxOrder() {
  TCity* city = this->cityField08;
  const short weightIndex = this->resourceTypeIndex48;
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
  return static_cast<short>(static_cast<short>(this->quantityField04) + static_cast<short>(limit));
}

// FUNCTION: IMPERIALISM 0x004b8800
bool TShipOrder::SetQuantity(short quantity) {
  TCity* city = this->cityField08;
  const short priorQuantity = this->quantityField04;
  const short delta = quantity - priorQuantity;
  const short weightIndex = this->resourceTypeIndex48;
  const short maxAllowed = static_cast<short>(this->MaxOrder());

  if (maxAllowed < quantity || quantity < 0) {
    return 0;
  }

  this->quantityField04 = quantity;

  city->cityStockLumberC8 =
      static_cast<short>(city->cityStockLumberC8 -
                         ReadWeight(g_industryActionCostWeightResCode09, weightIndex) * delta);
  city->Refresh80();
  city->cityStockFabricC6 =
      static_cast<short>(city->cityStockFabricC6 -
                         ReadWeight(g_industryActionCostWeightResCode08, weightIndex) * delta);
  city->Refresh80();
  city->cityStockArmsD6 =
      static_cast<short>(city->cityStockArmsD6 -
                         ReadWeight(g_industryActionCostWeightResCode10, weightIndex) * delta);
  city->Refresh80();
  city->cityStockSteelCC =
      static_cast<short>(city->cityStockSteelCC -
                         ReadWeight(g_industryActionCostWeightResCode0B, weightIndex) * delta);
  city->Refresh80();
  city->cityStockCoalBC =
      static_cast<short>(city->cityStockCoalBC -
                         ReadWeight(g_industryActionCostWeightResCode03, weightIndex) * delta);
  city->Refresh80();
  city->cityStockFuelCE =
      static_cast<short>(city->cityStockFuelCE -
                         ReadWeight(g_industryActionCostWeightResCode0C, weightIndex) * delta);
  city->Refresh80();
  return 1;
}

// FUNCTION: IMPERIALISM 0x004b8970
undefined TShipOrder::CommitIfPending() {
  if (this->resourceTypeIndex48 != 0 && this->quantityField04 != 0) {
    this->CommitQueuedNavyOrdersAndUpdateTierByCapability();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b89a0
void TShipOrder::CommitQueuedNavyOrdersAndUpdateTierByCapability() {
  short quantity = this->quantityField04;
  TCity* city = this->cityField08;

  city->productionOrderTable1dc[this->resourceTypeIndex48] =
      static_cast<short>(city->productionOrderTable1dc[this->resourceTypeIndex48] + quantity);
  this->quantityField04 = static_cast<short>(quantity - 1);

  while (quantity != 0) {
    const int nationSlot = static_cast<int>(city->ownerNationAc->nationSlot);
    TZone* portZone =
        static_cast<TZone*>(g_pActiveMapOrderContext->FindPortZoneBySelectedTile(city));
    CreateNavyPrimaryOrderNodeAndAssignDisplayName(this->resourceTypeIndex48, portZone, nationSlot,
                                                   0);
    quantity = this->quantityField04;
    this->quantityField04 = static_cast<short>(quantity - 1);
  }

  ZeroShipOrderTrackingSlots(this);
  this->quantityField04 = 0;

  TGreatPower* owner = city->ownerNationAc;
  if (*reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(owner) + 0x8c8) == '2') {
    return;
  }

  short currentCapability = owner->GetCityBuildingProductionSlot8D(2);
  short desiredCapability;
  if (*reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(owner) + 0x8c8) == '\0') {
    desiredCapability = 0;
  } else {
    desiredCapability = static_cast<short>(
        *reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(owner) + 0x8c8) - 0x33);
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
undefined TShipOrder::FillOrderSheet() {
  return 0;
}
