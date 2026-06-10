#pragma once

#include "decomp_types.h"

struct TPtrList;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// City production-summary object kept at TCity+0x1d8 (vtable + inline fields).
// Slot 0x50 hands out the raw per-resource summary short array that TCity slot 0x1d
// adjusts by the city's reserved amounts.
class TCitySummaryObject {
public:
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void Release1C() = 0; // slot 0x1c
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void s0a() = 0;
  // slot 0x2c — production preset notification (TGreatPower slot 0x39, 0x004df810).
  virtual void NotifyProductionPresetSlot2C(int a, int b, int c) = 0;
  virtual void s0c() = 0;
  virtual void s0d() = 0;
  virtual void s0e() = 0;
  virtual void s0f() = 0;
  virtual void s10() = 0;
  virtual void s11() = 0;
  virtual void s12() = 0;
  virtual void s13() = 0;
  // slot 0x50 — raw summary short array (indexed 0..0x16; 0x004b44d0).
  virtual short* GetSummaryArraySlot50() = 0;

  unsigned char pad04[0x1c - 0x04];
  short stockLevel1c; // +0x1c — slot 0x0b derives lowSummaryFlag7d from it
};

// The per-nation city/production model ("relation manager" at TGreatPower+0x894).
// RTTI: g_pClassDescTCity @ 0x0064f338; created by CreateTCityInstance (0x004b2340).
// Like TGreatPower, the destructor restores the RefCountedObjectBase vtable
// (0x0066fec4) — real base inheritance is still future work.
// VTABLE: IMPERIALISM 0x0064f580
class TCity {
public:
  // slot 0x00 — body 0x004b2490: class descriptor pointer.
  virtual void* GetClassDescPointerSlot00();
  // slot 0x01 — scalar deleting destructor 0x004b2520 (SYNTHETIC); real dtor body
  // 0x004b2550 only restores the base vtable.
  virtual ~TCity();
  virtual void TurnEventSlot08_Provisional() {}
  virtual void NoOpSlot0C_Provisional() {}
  virtual void NoOpSlot10_Provisional() {}
  // slot 0x05 — body 0x004b35d0 (915B, unported): serialize production state.
  virtual void SerializeCityProductionState(int stream) {
    (void)stream;
  }
  // slot 0x06 — body 0x004b30a0 (1044B, unported): deserialize production state.
  virtual void Call18(int arg1 = 0) {
    (void)arg1;
  }
  // slot 0x07 — body 0x004b3a60: release every owned order object then `delete this`.
  virtual void Call1C();
  virtual void TurnEventSlot20_Provisional() {}
  virtual void TurnEventSlot24_Provisional() {}
  // slot 0x0a — body 0x004b3b40 (528B, unported).
  virtual void Call28() {}
  // slot 0x0b — body 0x004b3de0: refresh the low-stock/low-summary flags and push
  // fieldB6 to the owner (TGreatPower slot 0x3f).
  virtual void Call2C();
  // slot 0x0c — body 0x004b3e70: dispatch pending build/ship orders to the owner
  // (slot 0xb0) then tick every owned order object (vt+0x34).
  virtual void RefreshOrderStateSlot0C();
  // slot 0x0d — body 0x004b3fb0: add a 17-entry need vector into the fieldB6 block
  // (split 7/6/4 across fieldB6/fieldC4/fieldD0).
  virtual void AddNeedVectorSplitSlot34(short* needVector);
  // slot 0x0e — body 0x004b4090: fieldB6[i] += owner->needTargetByType[i]; clears
  // relationNeedSlotE0/E2.
  virtual void AddOwnerNeedTargetsSlot38();
  // slot 0x0f — body 0x004b4040: fieldB6[i] += amounts[i]; clears E0/E2.
  virtual void AddNeedVectorSlot3C(short* amounts);
  // slot 0x10 — body 0x004b4580 (247B, unported): create the Altown city object.
  virtual void CreateAltownCityObjectSlot40() {}
  // slot 0x11 — body 0x004b3b20: adopt the selected order/marker (TGreatPower slots
  // 0x3a/0x3b hand the new Frog City marker through this).
  virtual void AdoptSelectedOrderSlot44(void* order);
  // slot 0x12 — body 0x004b4540: pack two shorts and write them to eventQueue274
  // (slot 0x38).
  virtual void WriteQueuePairSlot48(short low, short high);
  // slot 0x13 — body 0x004b40e0: allocate up to `amount` of a need from the owner's
  // current-over-target surplus (capped by needCapA6 - overCap), accumulate into
  // fieldB6 and push the new target (TGreatPower slot 0x45).
  virtual short AllocateNeedFromOwnerSlot4C(short needIndex, short amount);
  // slot 0x14 — body 0x004b46c0: forward to queue274 slot 0x20.
  virtual void ForwardQueueSlot20Slot50();
  // slot 0x15 — thunk 0x00407464: building display capacity by slot.
  virtual short GetCityBuildingDisplayCapacityBySlot(int buildingSlot) {
    (void)buildingSlot;
    return 0;
  }
  // slot 0x16 — body 0x004b48a0: capacity tier (1..4) for a building slot, with the
  // tighter thresholds for slots 1/3/5.
  virtual char GetBuildingCapacityTierSlot58(int buildingSlot);
  // slot 0x17 — body 0x004b4940 (577B, unported).
  virtual void Slot5C_Provisional() {}
  // slot 0x18 — thunk 0x0040494e: toggle the power-plant upgrade order.
  virtual void ToggleCityPowerPlantUpgradeOrderSlot60() {}
  // slot 0x19 — body 0x004b4c80: write the production flag/current/accum for a slot.
  virtual void SetProductionSlotState(short productionSlot, char flag, short current, short accum);
  // slot 0x1a — body 0x004b4cc0: read the production flag byte (+0x21c) and the two
  // production shorts (+0x22c/+0x24c) for a slot.
  virtual char ReadProductionSlotState(short productionSlot, short* outCurrent, short* outAccum);
  // slot 0x1b — body 0x004b4230: owner needCapA6 (0 when unowned).
  virtual int GetOwnerNeedCapA6();
  // slot 0x1c — body 0x004b4260: set owner needCapA6.
  virtual void SetOwnerNeedCapA6(short value);
  // slot 0x1d — body 0x004b44d0: subtract the city's reserved amounts from the raw
  // summary array and return it (shorts at +0x22/+0x24/+0x28 summed by TGreatPower
  // slot 0x65, body 0x004dd7f0).
  virtual short* GetCitySummaryRecordSlot74();
  // slot 0x1e — body 0x004b4d00: true for the basic resource slots 0..6 and 0xb.
  virtual short IsBasicResourceSlot78(short resourceSlot);
  virtual void Slot7C_Provisional() {}
  // slot 0x20 — body 0x004b4180: clamp negative fieldB6 entries to 0 (asserting via
  // UCity.cpp:0x47f unless replaying).
  virtual void Refresh80();

  short field04; // +0x04
  short field06; // +0x06 — zeroed by the ctor
  short field08; // +0x08 — zeroed by the ctor
  unsigned char pad0a[0x5c - 0x0a];
  // 0x5c..0x68 — per-zone recruit order counters (pending-action FSM, 0x004dab20).
  short recruitZoneCount5c[6];
  short navySecondaryCount68; // 0x68 — navy secondary-order counter
  unsigned char pad6a[0x7c - 0x6a];
  unsigned char lowProductionFlag7c; // +0x7c — slot 0x0b
  unsigned char lowStockFlag7d;      // +0x7d — slot 0x0b
  // +0x7e..0xac — per-resource reserved amounts subtracted from the summary
  // (entry 0x13 doubles as the +0xa4 labor reserve in 0x004b44d0).
  short reservedByType7e[0x17];
  class TGreatPower* ownerNationAc; // 0xAC — owning nation state (0x004b4dc0)
  // 0xB0 — currently selected order; its +0x14 tile id drives the port-zone lookup
  // (0x005634a0).
  void* selectedOrderB0;
  unsigned char pad_b4[0xB6 - 0xB4];
  // 0xB6..0xE4; fieldB6[0x15]/[0x16] occupy 0xE0/0xE2 (relationNeedSlotE0/E2).
  short fieldB6[0x17];
  // 0xE4..0x1D8 — owned order objects, released through slot 0x1c on teardown.
  void* orderSlotsE4[0x3D];
  TCitySummaryObject* productionSummary1d8; // 0x1D8
  // 0x1DC — 16-entry per-city production order table (0x004b4dc0, ctor-cleared).
  short productionOrderTable1dc[0x10];
  short productionAccum1fc[0x10];         // 0x1FC — ctor-cleared
  unsigned char productionFlags21c[0x10]; // 0x21C — ctor-cleared
  short production22c[0x10];              // 0x22C — slot 0x1a outCurrent
  short production24c[0x10];              // 0x24C — slot 0x1a outAccum
  short field26c;                         // 0x26C — zeroed by the ctor
  short pad26e;
  TPtrList* trackedOrderList270;     // 0x270 — released via Call58
  class TQueueObject* eventQueue274; // 0x274 — released via Call24

  TCity(); // 0x004b24b0 ("InitializeCityModel")

  int GetBuildingProductionValueBySlot(short buildingSlot);

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
};
