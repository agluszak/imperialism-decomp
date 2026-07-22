#include "game/TCapacityOrder.h"
#include "game/global_data_tables.h"

#include "game/mfc.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/UiRuntimeContext.h"

#include <new>

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

static void ZeroTrackingSlots(TCapacityOrder* order) {
  int remaining;
  int* blockCursor = reinterpret_cast<int*>(order->trackingSlots10);

  remaining = 0xb;
  while (remaining != 0) {
    *blockCursor = 0;
    blockCursor = blockCursor + 1;
    remaining = remaining + -1;
  }
  *reinterpret_cast<short*>(blockCursor) = 0;
}

TCapacityOrder::TCapacityOrder(TCity* city) : TItemOrder() {
  quantityField04 = 0;
  cityField08 = city;
  summaryField0c = city != 0 ? city->productionSummary1d8 : 0;
  field3e = 0;
  field40 = 0;
  accumulatedValue = 0;
  resourceTypeIndex48 = 0;
  requestedQuantity4c = 0;
  primaryInputResourceId = 0;
  secondaryInputResourceId = 0;
  productionSlot = 0;
  ZeroTrackingSlots(this);
}

TCapacityOrder* TCapacityOrder::NewForCity(TCity* city) {
  return new TCapacityOrder(city);
}

bool TCapacityOrder::CanMakeFromCityStock() {
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
    return true;
  }
  return false;
}

bool TCapacityOrder::CanFillOrderSheet(OrderSheet* orderSheet) {
  const short weightIndex = this->resourceTypeIndex48;
  const short weight09 = ReadWeight(g_industryActionCostWeightResCode09, weightIndex);
  const short weight08 = ReadWeight(g_industryActionCostWeightResCode08, weightIndex);
  const short weight10 = ReadWeight(g_industryActionCostWeightResCode10, weightIndex);
  const short weight0B = ReadWeight(g_industryActionCostWeightResCode0B, weightIndex);
  const short weight03 = ReadWeight(g_industryActionCostWeightResCode03, weightIndex);
  const short weight0C = ReadWeight(g_industryActionCostWeightResCode0C, weightIndex);

  // Note: this checks a different set of order-sheet slots (0x11/0x10/0x18/0x13/0x0b/0x14)
  // than TShipOrder::FillOrderSheet writes (0x09/0x08/0x10/0x0b/0x03/0x0c) -- only indices
  // 0x10 and 0x0b overlap. TCapacityOrder is the industrial-capacity sibling, not naval.
  if (static_cast<int>(weight09) <=
          static_cast<int>(orderSheet->slotByResourceCode[0x11] + weight09) &&
      static_cast<int>(weight08) <=
          static_cast<int>(orderSheet->slotByResourceCode[0x10] + weight08) &&
      static_cast<int>(weight10) <=
          static_cast<int>(orderSheet->slotByResourceCode[0x18] + weight10) &&
      static_cast<int>(weight0B) <=
          static_cast<int>(orderSheet->slotByResourceCode[0x13] + weight0B) &&
      static_cast<int>(weight03) <=
          static_cast<int>(orderSheet->slotByResourceCode[0x0b] + weight03) &&
      static_cast<int>(weight0C) <=
          static_cast<int>(orderSheet->slotByResourceCode[0x14] + weight0C)) {
    return true;
  }
  return false;
}

short TCapacityOrder::ComputeCapacityOrderMaxQuantity() {
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

bool TCapacityOrder::SetCapacityOrderQuantity(short quantity) {
  TCity* city = this->cityField08;
  const short priorQuantity = this->quantityField04;
  const short delta = quantity - priorQuantity;
  const short weightIndex = this->resourceTypeIndex48;
  const short maxAllowed = this->ComputeCapacityOrderMaxQuantity();
  bool accepted;

  if (maxAllowed < quantity || quantity < 0) {
    accepted = false;
  } else {
    this->quantityField04 = quantity;
    accepted = true;
  }
  if (!accepted) {
    return false;
  }

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
  if (g_pUiRuntimeContext != 0) {
    g_pUiRuntimeContext->RefreshCityProductionUi();
  }
  return true;
}

void TCapacityOrder::CommitCapacityOrderIfPending() {
  if (this->resourceTypeIndex48 != 0 && this->quantityField04 != 0) {
    this->Produce();
  }
}

TCapacityOrder::TCapacityOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b8c90
// TCapacityOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b8cc0
// TCapacityOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCapacityOrder, TItemOrder)

// SYNTHETIC: IMPERIALISM 0x004b8d00
// TCapacityOrder::`scalar deleting destructor'

TCapacityOrder::~TCapacityOrder() {}
// FUNCTION: IMPERIALISM 0x004b8d50
void TCapacityOrder::ICapacityOrder(TCity* city, short resourceType, short primaryInputResource,
                                    short secondaryInputResource, short productionSlotValue) {
  this->cityField08 = city;
  this->summaryField0c = city->productionSummary1d8;
  this->resourceTypeIndex48 = resourceType;
  this->quantityField04 = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    this->trackingSlots10[resource] = 0;
  }
  this->accumulatedValue = 0;
  this->primaryInputResourceId = primaryInputResource;
  this->field40 = 0;
  this->field3e = 0;
  this->requestedQuantity4c = 0;
  this->secondaryInputResourceId = secondaryInputResource;
  this->productionSlot = productionSlotValue;
}

// FUNCTION: IMPERIALISM 0x004b8dd0
void TCapacityOrder::Produce() {
  TCity* city = this->cityField08;
  short slotIndex = this->resourceTypeIndex48;
  short newValue;
  short deltaToAccum;

  if (this->quantityField04 == 0) {
    return;
  }
  if (slotIndex == 0xe) {
    const short currentCap = static_cast<short>(city->GetOwnerNeedCapA6());
    city->SetOwnerNeedCapA6(static_cast<short>(currentCap + this->quantityField04));
    goto apply_done;
  }
  if (slotIndex == 0xf) {
    TGreatPower* owner = city->ownerNationAc;
    if (owner->field8d1 < '3') {
      int laborPool = owner->ownedRegionList->GetSize();
      if ((laborPool + ((laborPool < 0) ? 3 : 0)) >> 2 < 2) {
        newValue = 1;
      } else {
        laborPool = owner->ownedRegionList->GetSize();
        newValue = static_cast<short>((laborPool + ((laborPool < 0) ? 3 : 0)) >> 2);
      }
    } else {
      int laborPool = owner->ownedRegionList->GetSize();
      if (laborPool / 3 < 2) {
        newValue = 1;
      } else {
        laborPool = owner->ownedRegionList->GetSize();
        newValue = static_cast<short>(laborPool / 3);
      }
    }
  } else {
    newValue = city->productionOrderTable1dc[slotIndex];
  }
  newValue = static_cast<short>(newValue + this->quantityField04);
  deltaToAccum = static_cast<short>(newValue - city->productionOrderTable1dc[slotIndex]);
  city->productionAccum1fc[slotIndex] =
      static_cast<short>(city->productionAccum1fc[slotIndex] + deltaToAccum);
  city->productionOrderTable1dc[slotIndex] = newValue;
apply_done:
  this->requestedQuantity4c = 0;
  this->quantityField04 = 0;
  this->trackingSlots10[this->primaryInputResourceId] = 0;
  this->trackingSlots10[this->secondaryInputResourceId] = 0;
  this->field3e = 0;
}
