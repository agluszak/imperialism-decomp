#include "game/TCapacityOrder.h"

#include "game/mfc.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/UiRuntimeContext.h"

#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// GLOBAL: IMPERIALISM 0x0064f440
CRuntimeClass g_pClassDescTCapacityOrder = {nullptr, 0, 0, nullptr, nullptr};
// GLOBAL: IMPERIALISM 0x00695b50
char g_industryActionCostWeightResCode09;
// GLOBAL: IMPERIALISM 0x00695b70
char g_industryActionCostWeightResCode08;
// GLOBAL: IMPERIALISM 0x00695b90
char g_industryActionCostWeightResCode10;
// GLOBAL: IMPERIALISM 0x00695bb0
char g_industryActionCostWeightResCode0B;
// GLOBAL: IMPERIALISM 0x00695bd0
char g_industryActionCostWeightResCode03;
// GLOBAL: IMPERIALISM 0x00695bf0
char g_industryActionCostWeightResCode0C;

static __inline short ReadWeight(const char* tableBase, short index) {
  return *reinterpret_cast<const short*>(tableBase + static_cast<unsigned int>(index) * 2);
}

static __inline void WriteShort(void* base, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset) = value;
}

static __inline short ReadShort(void* base, int offset) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(base) + offset);
}

static __inline short* CityStockShort(TCity* city, int offset) {
  return reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(city) + offset);
}

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

int AllocateWithFallbackHandler(undefined4 size_bytes);

TCapacityOrder::TCapacityOrder(TCity* city)
    : quantityField04(0), cityField08(city),
      summaryField0c(city != 0 ? city->productionSummary1d8 : 0), field3e(0), field40(0),
      field44(0), resourceTypeIndex48(0), field4c(0), trackingIndex4e(0), trackingIndex50(0),
      field52(0) {
  ZeroTrackingSlots(this);
}

TCapacityOrder* TCapacityOrder::NewForCity(TCity* city) {
  void* storage = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x4c));
  if (storage == 0) {
    return 0;
  }
  return new (storage) TCapacityOrder(city);
}



// FUNCTION: IMPERIALISM 0x004b85a0
bool TCapacityOrder::CanMakeFromCityStock() {
  TCity* city = this->cityField08;

  if (ReadWeight(&g_industryActionCostWeightResCode09, this->resourceTypeIndex48) <=
          *CityStockShort(city, 0xc8) &&
      ReadWeight(&g_industryActionCostWeightResCode08, this->resourceTypeIndex48) <=
          *CityStockShort(city, 0xc6) &&
      ReadWeight(&g_industryActionCostWeightResCode10, this->resourceTypeIndex48) <=
          *CityStockShort(city, 0xd6) &&
      ReadWeight(&g_industryActionCostWeightResCode0B, this->resourceTypeIndex48) <=
          *CityStockShort(city, 0xcc) &&
      ReadWeight(&g_industryActionCostWeightResCode03, this->resourceTypeIndex48) <=
          *CityStockShort(city, 0xbc) &&
      ReadWeight(&g_industryActionCostWeightResCode0C, this->resourceTypeIndex48) <=
          *CityStockShort(city, 0xce)) {
    return true;
  }
  return false;
}



// FUNCTION: IMPERIALISM 0x004b8630
bool TCapacityOrder::CanFillOrderSheet(void* orderSheet) {
  const short weightIndex = this->resourceTypeIndex48;
  const short weight09 = ReadWeight(&g_industryActionCostWeightResCode09, weightIndex);
  const short weight08 = ReadWeight(&g_industryActionCostWeightResCode08, weightIndex);
  const short weight10 = ReadWeight(&g_industryActionCostWeightResCode10, weightIndex);
  const short weight0B = ReadWeight(&g_industryActionCostWeightResCode0B, weightIndex);
  const short weight03 = ReadWeight(&g_industryActionCostWeightResCode03, weightIndex);
  const short weight0C = ReadWeight(&g_industryActionCostWeightResCode0C, weightIndex);

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



// FUNCTION: IMPERIALISM 0x004b86d0
short TCapacityOrder::MaxOrder() {
  TCity* city = this->cityField08;
  const short weightIndex = this->resourceTypeIndex48;
  int limit = 10000;
  int candidate;

  if (ReadWeight(&g_industryActionCostWeightResCode09, weightIndex) != 0) {
    candidate = static_cast<int>(*CityStockShort(city, 0xc8)) /
                static_cast<int>(ReadWeight(&g_industryActionCostWeightResCode09, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(&g_industryActionCostWeightResCode08, weightIndex) != 0) {
    candidate = static_cast<int>(*CityStockShort(city, 0xc6)) /
                static_cast<int>(ReadWeight(&g_industryActionCostWeightResCode08, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(&g_industryActionCostWeightResCode10, weightIndex) != 0) {
    candidate = static_cast<int>(*CityStockShort(city, 0xd6)) /
                static_cast<int>(ReadWeight(&g_industryActionCostWeightResCode10, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(&g_industryActionCostWeightResCode03, weightIndex) != 0) {
    candidate = static_cast<int>(*CityStockShort(city, 0xbc)) /
                static_cast<int>(ReadWeight(&g_industryActionCostWeightResCode03, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(&g_industryActionCostWeightResCode0B, weightIndex) != 0) {
    candidate = static_cast<int>(*CityStockShort(city, 0xcc)) /
                static_cast<int>(ReadWeight(&g_industryActionCostWeightResCode0B, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  if (ReadWeight(&g_industryActionCostWeightResCode0C, weightIndex) != 0) {
    candidate = static_cast<int>(*CityStockShort(city, 0xce)) /
                static_cast<int>(ReadWeight(&g_industryActionCostWeightResCode0C, weightIndex));
    if (static_cast<short>(candidate) < static_cast<short>(limit)) {
      limit = candidate;
    }
  }
  return static_cast<short>(static_cast<short>(this->quantityField04) + static_cast<short>(limit));
}



// FUNCTION: IMPERIALISM 0x004b8800
bool TCapacityOrder::SetQuantity(short quantity) {
  TCity* city = this->cityField08;
  const short priorQuantity = this->quantityField04;
  const short delta = quantity - priorQuantity;
  const short weightIndex = this->resourceTypeIndex48;
  const short maxAllowed = this->MaxOrder();
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

  *CityStockShort(city, 0xc8) =
      static_cast<short>(*CityStockShort(city, 0xc8) -
                         ReadWeight(&g_industryActionCostWeightResCode09, weightIndex) * delta);
  city->Refresh80();
  *CityStockShort(city, 0xc6) =
      static_cast<short>(*CityStockShort(city, 0xc6) -
                         ReadWeight(&g_industryActionCostWeightResCode08, weightIndex) * delta);
  city->Refresh80();
  *CityStockShort(city, 0xd6) =
      static_cast<short>(*CityStockShort(city, 0xd6) -
                         ReadWeight(&g_industryActionCostWeightResCode10, weightIndex) * delta);
  city->Refresh80();
  *CityStockShort(city, 0xcc) =
      static_cast<short>(*CityStockShort(city, 0xcc) -
                         ReadWeight(&g_industryActionCostWeightResCode0B, weightIndex) * delta);
  city->Refresh80();
  *CityStockShort(city, 0xbc) =
      static_cast<short>(*CityStockShort(city, 0xbc) -
                         ReadWeight(&g_industryActionCostWeightResCode03, weightIndex) * delta);
  city->Refresh80();
  *CityStockShort(city, 0xce) =
      static_cast<short>(*CityStockShort(city, 0xce) -
                         ReadWeight(&g_industryActionCostWeightResCode0C, weightIndex) * delta);
  city->Refresh80();
  if (g_pUiRuntimeContext != 0) {
    g_pUiRuntimeContext->RefreshCityProductionUiSlotAc();
  }
  return true;
}



// FUNCTION: IMPERIALISM 0x004b8970
void TCapacityOrder::CommitIfPending() {
  if (this->resourceTypeIndex48 != 0 && this->quantityField04 != 0) {
    this->ApplyCityProductionSlotDelta();
  }
}



// FUNCTION: IMPERIALISM 0x004b8b80
void TCapacityOrder::FillOrderSheet(void* orderSheet, short quantity) {
  short value = 0;

  this->Produce(orderSheet);

  value = static_cast<short>(
      ReadWeight(&g_industryActionCostWeightResCode09, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x12, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x12, 0);
  }

  value = static_cast<short>(
      ReadWeight(&g_industryActionCostWeightResCode08, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x10, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x10, 0);
  }

  value = static_cast<short>(
      ReadWeight(&g_industryActionCostWeightResCode10, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x20, value);
  if (ReadShort(orderSheet, 0x12) < 0) {
    WriteShort(orderSheet, 0x12, 0);
  }

  value = static_cast<short>(
      ReadWeight(&g_industryActionCostWeightResCode0B, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x16, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x16, 0);
  }

  value = static_cast<short>(
      ReadWeight(&g_industryActionCostWeightResCode03, this->resourceTypeIndex48) * quantity);
  WriteShort(orderSheet, 0x06, value);
  if (value < 0) {
    WriteShort(orderSheet, 0x06, 0);
  }

  value = static_cast<short>(
      ReadWeight(&g_industryActionCostWeightResCode0C, this->resourceTypeIndex48) * quantity);
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


// FUNCTION: IMPERIALISM 0x004b8d50
void TCapacityOrder::ICapacityOrder(TCity* city, short resourceType, short trackingIndex4eInit,
                                    short trackingIndex50Init, short field52Init) {
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
}



// FUNCTION: IMPERIALISM 0x004b8dd0
void TCapacityOrder::ApplyCityProductionSlotDelta() {
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
}

undefined TCapacityOrder::OrphanRetStub_004b5160(void) { return 0;}

TCapacityOrder::~TCapacityOrder() {}
