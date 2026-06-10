#include "game/TCity.h"

#include "game/CString.h"
#include "game/TGreatPower.h"
#include "game/TLocalizationRuntime.h"
#include "game/TQueueObject.h"
#include "game/diplomacy_globals.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);

extern "C" {
// GLOBAL: IMPERIALISM 0x0064f338
char g_pClassDescTCity = 0;
// GLOBAL: IMPERIALISM 0x006a24d4
char g_Sanitize_City_Counter_Value_006A24D4 = 0;
}

static const char kUCityCppPath[] = "D:\\Ambit\\Cross\\UCity.cpp";

// FUNCTION: IMPERIALISM 0x004b24b0
TCity::TCity() {
  selectedOrderB0 = 0;
  trackedOrderList270 = 0;
  eventQueue274 = 0;
  for (int productionSlot = 0; productionSlot < 0x10; ++productionSlot) {
    productionOrderTable1dc[productionSlot] = 0;
    productionAccum1fc[productionSlot] = 0;
    productionFlags21c[productionSlot] = 0;
  }
  field26c = 0;
  field06 = 0;
  field08 = 0;
}

// The original tail restores the RefCountedObjectBase vtable (0x0066fec4); that
// write will come for free once TCity is modeled with its real base class.
// FUNCTION: IMPERIALISM 0x004b2550
TCity::~TCity() {}

// SYNTHETIC: IMPERIALISM 0x004b2520
// TCity::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004b2490
void* TCity::GetClassDescPointerSlot00() {
  return &g_pClassDescTCity;
}

// FUNCTION: IMPERIALISM 0x004b3a60
void TCity::Call1C() {
  if (this->productionSummary1d8 != 0) {
    this->productionSummary1d8->Release1C();
  }
  this->productionSummary1d8 = 0;
  void** orderSlot = this->orderSlotsE4;
  int remaining = 0x3d;
  do {
    if (*orderSlot != 0) {
      static_cast<TCitySummaryObject*>(*orderSlot)->Release1C();
    }
    *orderSlot = 0;
    ++orderSlot;
    --remaining;
  } while (remaining != 0);
  if (this->trackedOrderList270 != 0) {
    this->trackedOrderList270->Call58();
  }
  this->trackedOrderList270 = 0;
  if (this->eventQueue274 != 0) {
    this->eventQueue274->Call24();
  }
  this->eventQueue274 = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x004b3de0
void TCity::Call2C() {
  if (this->productionSummary1d8->stockLevel1c < 2) {
    this->lowStockFlag7d = 0;
  } else {
    this->lowStockFlag7d = 1;
  }
  short shortageCount = 3;
  if (this->productionAccum1fc[4] > 0) {
    shortageCount = 2;
  }
  if (this->productionAccum1fc[2] > 0) {
    shortageCount = static_cast<short>(shortageCount - 1);
  }
  if (this->productionAccum1fc[0] > 0) {
    shortageCount = static_cast<short>(shortageCount - 1);
  }
  if (shortageCount < 2) {
    this->lowProductionFlag7c = 1;
  } else {
    this->lowProductionFlag7c = 0;
  }
  this->ownerNationAc->AbsorbCityNeedVectorSlotFC_Provisional(this->fieldB6);
}

undefined4 thunk_GetResourceTypeRandomDrawBlockFlag(void); // 0x004b3e70 -> 0x00550d80

// City order entry view (orderSlotsE4 payloads, 0x004b3e70): pending count at +0x04,
// tile id at +0x48, per-turn tick at vt+0x34.
class TCityOrderEntryView {
public:
  virtual void o00() = 0;
  virtual void o01() = 0;
  virtual void o02() = 0;
  virtual void o03() = 0;
  virtual void o04() = 0;
  virtual void o05() = 0;
  virtual void o06() = 0;
  virtual void o07() = 0;
  virtual void o08() = 0;
  virtual void o09() = 0;
  virtual void o0a() = 0;
  virtual void o0b() = 0;
  virtual void o0c() = 0;
  virtual void TickSlot34() = 0;

  short pendingCount04;
  unsigned char pad06[0x48 - 0x06];
  short tileId48;
};

// FUNCTION: IMPERIALISM 0x004b3e70
void TCity::RefreshOrderStateSlot0C() {
  TCityOrderEntryView** shipOrderCursor =
      reinterpret_cast<TCityOrderEntryView**>(&this->orderSlotsE4[0x2b]);
  TCityOrderEntryView** orderCursor = shipOrderCursor;
  int remaining = 8;
  do {
    if (*orderCursor != 0) {
      CString orderName;
      short pendingCount = (*orderCursor)->pendingCount04;
      short tileId = (*orderCursor)->tileId48;
      if (pendingCount != 0) {
        short blockFlag =
            reinterpret_cast<short(__cdecl*)(int)>(thunk_GetResourceTypeRandomDrawBlockFlag)(
                tileId);
        if (blockFlag == 0) {
          this->ownerNationAc->DispatchTurnOrderActionSlotB0(1, tileId, pendingCount);
        } else {
          this->ownerNationAc->DispatchTurnOrderActionSlotB0(0, tileId, pendingCount);
        }
      }
    }
    ++orderCursor;
    --remaining;
  } while (remaining != 0);
  TCityOrderEntryView** buildOrderCursor =
      reinterpret_cast<TCityOrderEntryView**>(&this->orderSlotsE4[0x19]);
  remaining = 0x12;
  do {
    if (*buildOrderCursor != 0) {
      (*buildOrderCursor)->TickSlot34();
    }
    ++buildOrderCursor;
    --remaining;
  } while (remaining != 0);
  remaining = 8;
  do {
    if (*shipOrderCursor != 0) {
      (*shipOrderCursor)->TickSlot34();
    }
    ++shipOrderCursor;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x004b4540
void TCity::WriteQueuePairSlot48(short low, short high) {
  *(reinterpret_cast<short*>(&low) + 1) = high;
  this->eventQueue274->WritePackedIntSlot38(reinterpret_cast<int*>(&low));
}

// FUNCTION: IMPERIALISM 0x004b40e0
short TCity::AllocateNeedFromOwnerSlot4C(short needIndex, short amount) {
  TGreatPower* owner = this->ownerNationAc;
  short surplus =
      static_cast<short>(owner->needCurrentByType[needIndex] - owner->needTargetByType[needIndex]);
  if (surplus < amount) {
    amount = surplus;
  }
  if (static_cast<short>(owner->needCapA6 - owner->needsOverCapFlag) < amount) {
    amount = static_cast<short>(owner->needCapA6 - owner->needsOverCapFlag);
  }
  this->fieldB6[needIndex] = static_cast<short>(this->fieldB6[needIndex] + amount);
  this->ownerNationAc->UpdateNeedTargetAndAccumulateOverCap(
      needIndex, static_cast<short>(owner->needTargetByType[needIndex] + amount));
  return amount;
}

// FUNCTION: IMPERIALISM 0x004b4c80
void TCity::SetProductionSlotState(short productionSlot, char flag, short current, short accum) {
  this->productionFlags21c[productionSlot] = flag;
  this->production22c[productionSlot] = current;
  this->production24c[productionSlot] = accum;
}

// FUNCTION: IMPERIALISM 0x004b4d00
short TCity::IsBasicResourceSlot78(short resourceSlot) {
  if (resourceSlot != 0 && resourceSlot != 1 && resourceSlot != 2 && resourceSlot != 3 &&
      resourceSlot != 4 && resourceSlot != 5 && resourceSlot != 6 && resourceSlot != 0x0b) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004b3fb0
void TCity::AddNeedVectorSplitSlot34(short* needVector) {
  short* needCursor = this->fieldB6;
  int count = 7;
  short* sourceCursor = needVector;
  do {
    *needCursor = static_cast<short>(*needCursor + *sourceCursor);
    ++sourceCursor;
    ++needCursor;
    --count;
  } while (count != 0);
  sourceCursor = needVector + 7;
  needCursor = &this->fieldB6[7];
  count = 6;
  do {
    *needCursor = static_cast<short>(*needCursor + *sourceCursor);
    ++sourceCursor;
    ++needCursor;
    --count;
  } while (count != 0);
  needCursor = &this->fieldB6[0x0d];
  sourceCursor = needVector + 0x0d;
  count = 4;
  do {
    *needCursor = static_cast<short>(*needCursor + *sourceCursor);
    ++sourceCursor;
    ++needCursor;
    --count;
  } while (count != 0);
}

// FUNCTION: IMPERIALISM 0x004b4090
void TCity::AddOwnerNeedTargetsSlot38() {
  int count = 0x17;
  short* needCursor = this->fieldB6;
  short* targetCursor = this->ownerNationAc->needTargetByType;
  do {
    *needCursor = static_cast<short>(*needCursor + *targetCursor);
    --count;
    ++needCursor;
    ++targetCursor;
  } while (count != 0);
  this->fieldB6[0x16] = 0;
  this->fieldB6[0x15] = 0;
}

// FUNCTION: IMPERIALISM 0x004b4040
void TCity::AddNeedVectorSlot3C(short* amounts) {
  short* needCursor = this->fieldB6;
  int count = 0x17;
  do {
    short amount = *amounts;
    ++amounts;
    *needCursor = static_cast<short>(*needCursor + amount);
    ++needCursor;
    --count;
  } while (count != 0);
  this->fieldB6[0x16] = 0;
  this->fieldB6[0x15] = 0;
}

// FUNCTION: IMPERIALISM 0x004b3b20
void TCity::AdoptSelectedOrderSlot44(void* order) {
  this->selectedOrderB0 = order;
}

// FUNCTION: IMPERIALISM 0x004b46c0
void TCity::ForwardQueueSlot20Slot50() {
  this->eventQueue274->Call20();
}

// FUNCTION: IMPERIALISM 0x004b48a0
char TCity::GetBuildingCapacityTierSlot58(int buildingSlot) {
  short capacity = this->GetCityBuildingDisplayCapacityBySlot(buildingSlot);
  short slot = static_cast<short>(buildingSlot);
  if (slot == 1 || slot == 3 || slot == 5) {
    if (capacity < 4) {
      return 1;
    }
    if (capacity < 8) {
      return 2;
    }
    return static_cast<char>((0x0f < capacity) + 3);
  }
  if (capacity < 8) {
    return 1;
  }
  if (capacity < 0x10) {
    return 2;
  }
  return static_cast<char>((0x1f < capacity) + 3);
}

// FUNCTION: IMPERIALISM 0x004b4cc0
char TCity::ReadProductionSlotState(short productionSlot, short* outCurrent, short* outAccum) {
  *outCurrent = this->production22c[productionSlot];
  *outAccum = this->production24c[productionSlot];
  return static_cast<char>(this->productionFlags21c[productionSlot]);
}

// FUNCTION: IMPERIALISM 0x004b4230
int TCity::GetOwnerNeedCapA6() {
  if (this->ownerNationAc != 0) {
    return this->ownerNationAc->needCapA6;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b4260
void TCity::SetOwnerNeedCapA6(short value) {
  this->ownerNationAc->needCapA6 = value;
}

// FUNCTION: IMPERIALISM 0x004b44d0
short* TCity::GetCitySummaryRecordSlot74() {
  short* summary = this->productionSummary1d8->GetSummaryArraySlot50();
  for (short resourceType = 0; resourceType < 0x17; ++resourceType) {
    short remaining = summary[resourceType];
    if (remaining != 0) {
      remaining = static_cast<short>(remaining - this->reservedByType7e[resourceType]);
      summary[resourceType] = remaining;
      if (resourceType == 0x14) {
        summary[0x14] = static_cast<short>(remaining - this->reservedByType7e[0x13]);
      }
      if (summary[resourceType] < 0) {
        summary[resourceType] = 0;
      }
    }
  }
  return summary;
}

// FUNCTION: IMPERIALISM 0x004b4180
void TCity::Refresh80() {
  int count = 0x17;
  short* needCursor = this->fieldB6;
  do {
    if (*needCursor < 0) {
      char dispatchGate = this->ownerNationAc->ShouldDispatchImmediatelySlot28_Provisional();
      if ((dispatchGate == 0 ||
           g_pLocalizationTable->redrawEnabled != 2) &&
          g_Sanitize_City_Counter_Value_006A24D4 == 0) {
        reinterpret_cast<void(__cdecl*)(const char*, int)>(
            thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(kUCityCppPath, 0x47f);
      }
      *needCursor = 0;
    }
    ++needCursor;
    --count;
  } while (count != 0);
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// Reads the persisted city production order for a building slot; slot 15 derives
// the value from the owned-region count (quartered, or thirded once status flag 9
// reaches its handled state), floored at 1.
#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004b4dc0
int TCity::GetBuildingProductionValueBySlot(short buildingSlot) {
  if (buildingSlot != 0xf) {
    return this->productionOrderTable1dc[buildingSlot];
  }
  TGreatPower* owner = this->ownerNationAc;
  if (static_cast<signed char>(owner->serializedStatusFlags[9]) < 0x33) {
    if (owner->ownedRegionList->GetCountOrReleaseSlot28() / 4 > 1) {
      return this->ownerNationAc->ownedRegionList->GetCountOrReleaseSlot28() / 4;
    }
  } else {
    if (owner->ownedRegionList->GetCountOrReleaseSlot28() / 3 > 1) {
      return this->ownerNationAc->ownedRegionList->GetCountOrReleaseSlot28() / 3;
    }
  }
  return 1;
}
#pragma optimize("", on)
