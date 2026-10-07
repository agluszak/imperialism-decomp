#include "game/resource_domain_types.h"
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
#include "game/globals/ui_core_globals.h"
#include "game/ui_core/TViewMgr.h"

static short ReadWeight(const short* tableBase, short index) {
  return tableBase[index];
}

enum {
  kResourceWeightIndex03 = 3,
  kResourceWeightIndex08 = 8,
  kResourceWeightIndex09 = 9,
  kResourceWeightIndex0B = 11,
  kResourceWeightIndex0C = 12,
  kResourceWeightIndex10 = 16,
};

IMPLEMENT_DYNCREATE(TShipOrder, TProductionOrder)

// FUNCTION: IMPERIALISM 0x004b85a0
bool TShipOrder::AutoCanMakeProduct() {
  TCity* city = ownerCity;

  return ReadWeight(g_industryActionCostWeightResCode09, resourceTypeIndex) <=
             city->stockByType[kResourceLumber] &&
         ReadWeight(g_industryActionCostWeightResCode08, resourceTypeIndex) <=
             city->stockByType[kResourceFabric] &&
         ReadWeight(g_industryActionCostWeightResCode10, resourceTypeIndex) <=
             city->stockByType[kResourceArms] &&
         ReadWeight(g_industryActionCostWeightResCode0B, resourceTypeIndex) <=
             city->stockByType[kResourceSteel] &&
         ReadWeight(g_industryActionCostWeightResCode03, resourceTypeIndex) <=
             city->stockByType[kResourceCoal] &&
         ReadWeight(g_industryActionCostWeightResCode0C, resourceTypeIndex) <=
             city->stockByType[kResourceFuel];
}

// FUNCTION: IMPERIALISM 0x004b8630
bool TShipOrder::CanMakeProduct() {
  const short weightIndex = resourceTypeIndex;
  const short weight09 = ReadWeight(g_industryActionCostWeightResCode09, weightIndex);
  const short weight08 = ReadWeight(g_industryActionCostWeightResCode08, weightIndex);
  const short weight10 = ReadWeight(g_industryActionCostWeightResCode10, weightIndex);
  const short weight0B = ReadWeight(g_industryActionCostWeightResCode0B, weightIndex);
  const short weight03 = ReadWeight(g_industryActionCostWeightResCode03, weightIndex);
  const short weight0C = ReadWeight(g_industryActionCostWeightResCode0C, weightIndex);

  return static_cast<int>(weight09) <=
             static_cast<int>(trackingSlots[kResourceWeightIndex09] + weight09) &&
         static_cast<int>(weight08) <=
             static_cast<int>(trackingSlots[kResourceWeightIndex08] + weight08) &&
         static_cast<int>(weight10) <=
             static_cast<int>(trackingSlots[kResourceWeightIndex10] + weight10) &&
         static_cast<int>(weight0B) <=
             static_cast<int>(trackingSlots[kResourceWeightIndex0B] + weight0B) &&
         static_cast<int>(weight03) <=
             static_cast<int>(trackingSlots[kResourceWeightIndex03] + weight03) &&
         static_cast<int>(weight0C) <=
             static_cast<int>(trackingSlots[kResourceWeightIndex0C] + weight0C);
}

// FUNCTION: IMPERIALISM 0x004b86d0
short TShipOrder::MaxOrder() {
  TCity* city = ownerCity;
  const short weightIndex = resourceTypeIndex;
  int limit = 10000;
  int candidate;

  if (ReadWeight(g_industryActionCostWeightResCode09, weightIndex) != 0) {
    candidate = static_cast<int>(city->stockByType[kResourceLumber]) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode09, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode08, weightIndex) != 0) {
    candidate = static_cast<int>(city->stockByType[kResourceFabric]) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode08, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode10, weightIndex) != 0) {
    candidate = static_cast<int>(city->stockByType[kResourceArms]) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode10, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode03, weightIndex) != 0) {
    candidate = static_cast<int>(city->stockByType[kResourceCoal]) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode03, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode0B, weightIndex) != 0) {
    candidate = static_cast<int>(city->stockByType[kResourceSteel]) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode0B, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(g_industryActionCostWeightResCode0C, weightIndex) != 0) {
    candidate = static_cast<int>(city->stockByType[kResourceFuel]) /
                static_cast<int>(ReadWeight(g_industryActionCostWeightResCode0C, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  return quantity + static_cast<short>(limit);
}

// FUNCTION: IMPERIALISM 0x004b8800
bool TShipOrder::SetQuantity(short quantity) {
  const short delta = quantity - this->quantity;

  if (!TProductionOrder::SetQuantity(quantity)) {
    return false;
  }

  ownerCity->stockByType[kResourceLumber] = static_cast<short>(
      ownerCity->stockByType[kResourceLumber] -
      ReadWeight(g_industryActionCostWeightResCode09, resourceTypeIndex) * delta);
  ownerCity->VerifyStocks();
  ownerCity->stockByType[kResourceFabric] = static_cast<short>(
      ownerCity->stockByType[kResourceFabric] -
      ReadWeight(g_industryActionCostWeightResCode08, resourceTypeIndex) * delta);
  ownerCity->VerifyStocks();
  ownerCity->stockByType[kResourceArms] = static_cast<short>(
      ownerCity->stockByType[kResourceArms] -
      ReadWeight(g_industryActionCostWeightResCode10, resourceTypeIndex) * delta);
  ownerCity->VerifyStocks();
  ownerCity->stockByType[kResourceSteel] = static_cast<short>(
      ownerCity->stockByType[kResourceSteel] -
      ReadWeight(g_industryActionCostWeightResCode0B, resourceTypeIndex) * delta);
  ownerCity->VerifyStocks();
  ownerCity->stockByType[kResourceCoal] = static_cast<short>(
      ownerCity->stockByType[kResourceCoal] -
      ReadWeight(g_industryActionCostWeightResCode03, resourceTypeIndex) * delta);
  ownerCity->VerifyStocks();
  ownerCity->stockByType[kResourceFuel] = static_cast<short>(
      ownerCity->stockByType[kResourceFuel] -
      ReadWeight(g_industryActionCostWeightResCode0C, resourceTypeIndex) * delta);
  ownerCity->VerifyStocks();
  g_pViewMgr->UpdateCityScreen();
  return true;
}

// FUNCTION: IMPERIALISM 0x004b8970
void TShipOrder::Produce() {
  if (resourceTypeIndex != 0 && quantity != 0) {
    LaunchShip();
  }
}

// FUNCTION: IMPERIALISM 0x004b89a0
void TShipOrder::LaunchShip() {
  short resourceTypeIndex = this->resourceTypeIndex;
  TCity* city = ownerCity;

  city->orderCountByType[resourceTypeIndex] =
      static_cast<short>(city->orderCountByType[resourceTypeIndex] + this->quantity);
  short quantity = this->quantity;
  this->quantity = static_cast<short>(quantity - 1);

  while (quantity != 0) {
    const int nationSlot = city->ownerNation->nationSlot;
    TZone* portZone = g_pActiveMapOrderContext->FindPortZoneBySelectedTile(city);
    CreateAdmiral(this->resourceTypeIndex, portZone, nationSlot, 0);
    quantity = this->quantity;
    this->quantity = static_cast<short>(quantity - 1);
  }

  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    trackingSlots[resource] = 0;
  }
  this->quantity = 0;

  TGreatPower* owner = city->ownerNation;
  if (owner->pendingActionStatus.byAction[0] == '2') {
    return;
  }

  short currentCapability = owner->GetArmsInNavy();
  short desiredCapability;
  if (owner->pendingActionStatus.byAction[0] == '\0') {
    desiredCapability = 0;
  } else {
    desiredCapability = static_cast<short>(owner->pendingActionStatus.byAction[0] - 0x33);
  }

  if (currentCapability < 0x19) {
    return;
  }
  if (currentCapability < 0x32) {
    if (desiredCapability != 0) {
      return;
    }
    owner->SetNationPendingActionStateAndPayload(0, 1);
    return;
  }
  if (currentCapability < 100) {
    if (desiredCapability >= 2) {
      return;
    }
    owner->SetNationPendingActionStateAndPayload(0, 2);
    return;
  }
  if (currentCapability < 200) {
    if (desiredCapability >= 3) {
      return;
    }
    owner->SetNationPendingActionStateAndPayload(0, 3);
    return;
  }
  if (currentCapability < 300) {
    if (desiredCapability >= 4) {
      return;
    }
    owner->SetNationPendingActionStateAndPayload(0, 4);
    return;
  }
  if (currentCapability < 400) {
    if (desiredCapability >= 5) {
      return;
    }
    owner->SetNationPendingActionStateAndPayload(0, 5);
    return;
  }
  if (currentCapability < 500 && desiredCapability < 6) {
    owner->SetNationPendingActionStateAndPayload(0, 6);
  }
}

// FUNCTION: IMPERIALISM 0x004b8b80
void TShipOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  short value;

  ResetOrderSheet(orderSheet);

  value = static_cast<short>(ReadWeight(g_industryActionCostWeightResCode09, resourceTypeIndex) *
                             quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex09] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex09] = 0;
  }

  value = static_cast<short>(ReadWeight(g_industryActionCostWeightResCode08, resourceTypeIndex) *
                             quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex08] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex08] = 0;
  }

  value = static_cast<short>(ReadWeight(g_industryActionCostWeightResCode10, resourceTypeIndex) *
                             quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex10] = value;
  // Matches the original: this clamp re-checks index 09, not the index 10 just written.
  if (orderSheet->slotByResourceCode[kResourceWeightIndex09] < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex09] = 0;
  }

  value = static_cast<short>(ReadWeight(g_industryActionCostWeightResCode0B, resourceTypeIndex) *
                             quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex0B] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex0B] = 0;
  }

  value = static_cast<short>(ReadWeight(g_industryActionCostWeightResCode03, resourceTypeIndex) *
                             quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex03] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex03] = 0;
  }

  value = static_cast<short>(ReadWeight(g_industryActionCostWeightResCode0C, resourceTypeIndex) *
                             quantity);
  orderSheet->slotByResourceCode[kResourceWeightIndex0C] = value;
  if (value < 0) {
    orderSheet->slotByResourceCode[kResourceWeightIndex0C] = 0;
  }
}
