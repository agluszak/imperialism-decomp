#include "game/TCapacityOrder.h"
#include "game/global_data_tables.h"
#include "game/order_weight_helpers.h"

#include "game/mfc.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/UiRuntimeContext.h"

#include <new>

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


TCapacityOrder::TCapacityOrder(TCity* city)
    : quantityField04(0), cityField08(city),
      summaryField0c(city != 0 ? city->productionSummary1d8 : 0), field3e(0), field40(0),
      field44(0), resourceTypeIndex48(0), field4c(0), trackingIndex4e(0), trackingIndex50(0),
      field52(0) {
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



bool TCapacityOrder::CanFillOrderSheet(void* orderSheet) {
  const short weightIndex = this->resourceTypeIndex48;
  const short weight09 = ReadWeight(g_industryActionCostWeightResCode09, weightIndex);
  const short weight08 = ReadWeight(g_industryActionCostWeightResCode08, weightIndex);
  const short weight10 = ReadWeight(g_industryActionCostWeightResCode10, weightIndex);
  const short weight0B = ReadWeight(g_industryActionCostWeightResCode0B, weightIndex);
  const short weight03 = ReadWeight(g_industryActionCostWeightResCode03, weightIndex);
  const short weight0C = ReadWeight(g_industryActionCostWeightResCode0C, weightIndex);

  if (static_cast<int>(weight09) <= static_cast<int>(ReadShort(orderSheet, 0x22) + weight09) &&
      static_cast<int>(weight08) <= static_cast<int>(ReadShort(orderSheet, 0x20) + weight08) &&
      static_cast<int>(weight10) <= static_cast<int>(ReadShort(orderSheet, 0x30) + weight10) &&
      static_cast<int>(weight0B) <= static_cast<int>(ReadShort(orderSheet, 0x26) + weight0B) &&
      static_cast<int>(weight03) <= static_cast<int>(ReadShort(orderSheet, 0x16) + weight03) &&
      static_cast<int>(weight0C) <= static_cast<int>(ReadShort(orderSheet, 0x28) + weight0C)) {
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
  if (g_pUiRuntimeContext != 0) {
    g_pUiRuntimeContext->RefreshCityProductionUiSlotAc();
  }
  return true;
}



void TCapacityOrder::CommitCapacityOrderIfPending() {
  if (this->resourceTypeIndex48 != 0 && this->quantityField04 != 0) {
    this->CommitIfPending();
  }
}



void TCapacityOrder::FillOrderSheet(void* orderSheet, short quantity) {
  short value = 0;

  this->InitializeCityOrderItemWorkingBuffers(reinterpret_cast<undefined4*>(orderSheet));

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode09, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x12, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x12, 0);
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode08, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x10, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x10, 0);
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode10, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x20, value);
  if (ReadShort(orderSheet, 0x12) < 0) {
    WriteShort(orderSheet, 0x12, 0);
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode0B, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x16, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x16, 0);
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode03, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x06, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x06, 0);
  }

  value = static_cast<short>(
      ReadWeight(g_industryActionCostWeightResCode0C, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x18, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x18, 0);
  }
}



// FUNCTION: IMPERIALISM 0x004b8cc0
CRuntimeClass* TCapacityOrder::GetRuntimeClass() const {
  return &g_pClassDescTCapacityOrder;
}



// SYNTHETIC: IMPERIALISM 0x004b8d00
// TCapacityOrder::`scalar deleting destructor'

TCapacityOrder::~TCapacityOrder() {}
// FUNCTION: IMPERIALISM 0x004b8d50
undefined TCapacityOrder::InitializeCityProductionState_Impl_At004b8d50(
    TCity* city, short resourceType, short trackingIndex4eInit, short trackingIndex50Init,
    short field52Init) {
  this->cityField08 = city;
  this->summaryField0c = city->productionSummary1d8;
  this->resourceTypeIndex48 = resourceType;
  this->quantityField04 = 0;
  ZeroTrackingSlots(this);
  this->field44 = 0;
  this->trackingIndex4e = trackingIndex4eInit;
  this->field40 = 0;
  this->field3e = 0;
  this->field4c = 0;
  this->trackingIndex50 = trackingIndex50Init;
  this->field52 = field52Init;
  return 0;
}



// FUNCTION: IMPERIALISM 0x004b8dd0
undefined TCapacityOrder::CommitIfPending() {
  TCity* city = this->cityField08;
  short slotIndex = this->resourceTypeIndex48;
  short newValue;
  short deltaToAccum;

  if (this->quantityField04 == 0) {
    return 0;
  }
  if (slotIndex == 0xe) {
    const short currentCap = static_cast<short>(city->GetOwnerNeedCapA6());
    city->SetOwnerNeedCapA6(static_cast<short>(currentCap + this->quantityField04));
    goto apply_done;
  }
  if (slotIndex == 0xf) {
    TGreatPower* owner = city->ownerNationAc;
    if (*reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(owner) + 0x8d1) < '3') {
      int laborPool = owner->ownedRegionList->GetCountSlot48();
      if ((laborPool + ((laborPool < 0) ? 3 : 0)) >> 2 < 2) {
        newValue = 1;
      } else {
        laborPool = owner->ownedRegionList->GetCountSlot48();
        newValue = static_cast<short>((laborPool + ((laborPool < 0) ? 3 : 0)) >> 2);
      }
    } else {
      int laborPool = owner->ownedRegionList->GetCountSlot48();
      if (laborPool / 3 < 2) {
        newValue = 1;
      } else {
        laborPool = owner->ownedRegionList->GetCountSlot48();
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
  this->field4c = 0;
  this->quantityField04 = 0;
  this->trackingSlots10[this->trackingIndex4e] = 0;
  this->trackingSlots10[this->trackingIndex50] = 0;
  this->field3e = 0;
  return 0;
}
