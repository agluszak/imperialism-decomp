#pragma once

#include "decomp_types.h"
#include "game/TObject.h"

struct TPtrList;
class TStream;

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
  virtual void Free() = 0;
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
protected:
  ~TCitySummaryObject() {}
};

// The per-nation city/production model at TGreatPower+0x894 (field `city`).
// RTTI: g_pClassDescTCity @ 0x0064f338; created by CreateTCityInstance (0x004b2340).
// LAYOUT: RECOVERED
// VTABLE: IMPERIALISM 0x0064f580
class TCity : public TObject {
public:
// === BEGIN GENERATED DECLS (TCity) — refreshed by recover-class; do not hand-edit ===
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanCallChain_C13_I161_004b3b40(); // slot 0x0a 0x4b3b40
  virtual undefined OrphanTiny_SetDwordEcxOffset_b0_004b3b20(); // slot 0x11 0x4b3b20
  virtual undefined OrphanLeaf_NoCall_Ins03_004b46c0(); // slot 0x14 0x4b46c0
  virtual undefined WrapperFor_GetActiveNationId_At004b4940(); // slot 0x17 0x4b4940
  virtual undefined OrphanLeaf_NoCall_Ins08_004b4c80(); // slot 0x19 0x4b4c80
  virtual undefined OrphanLeaf_NoCall_Ins11_004b4cc0(); // slot 0x1a 0x4b4cc0
  virtual undefined OrphanLeaf_NoCall_Ins07_004b4230(); // slot 0x1b 0x4b4230
  virtual undefined OrphanLeaf_NoCall_Ins04_004b4260(); // slot 0x1c 0x4b4260
  virtual undefined OrphanRetStub_004b4210(); // slot 0x1f 0x4b4210
// === END GENERATED DECLS (TCity) ===
  CRuntimeClass* GetRuntimeClass() const override;
  ~TCity() override;

  // slots 0x05–0x07 — TObject stream lifecycle (bodies 0x004b35d0 / 0x004b30a0 / 0x004b3a60).
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  // slot 0x0a — body 0x004b3b40 (528B, unported).
  virtual void Call28();
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
  virtual void CreateAltownCityObject();
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
  virtual void ForwardQueueSlot20Slot50(void* message = 0);
  // slot 0x15 — body 0x004b46e0 (vtable stores direct body, not ILT 0x00407464).
  virtual short GetCityBuildingDisplayCapacityBySlot(int buildingSlot);
  // slot 0x16 — body 0x004b48a0: capacity tier (1..4) for a building slot, with the
  // tighter thresholds for slots 1/3/5.
  virtual char GetBuildingCapacityTierSlot58(int buildingSlot);
  // slot 0x17 — body 0x004b4940 (577B, unported).
  virtual int GetActiveNationBuildingMetricSlot5C(short buildingSlot);
  // slot 0x18 — body 0x004b4d50 (vtable stores direct body, not ILT 0x0040494e).
  virtual void ToggleCityPowerPlantUpgradeOrder(char enableUpgrade);
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
  // slot 0x1f — body 0x004b4210.
  virtual void NoOpCitySlot7C();
  // slot 0x20 — body 0x004b4180: clamp negative fieldB6 entries to 0 (asserting via
  // UCity.cpp:0x47f unless replaying).
  virtual void Refresh80();

  short field04; // +0x04
  short field06; // +0x06 — zeroed by the ctor
  short field08; // +0x08 — zeroed by the ctor
  unsigned char pad0a[0x5c - 0x0a];
  // +0x5c..+0x68 — per-zone recruit order counters (pending-action FSM, 0x004dab20).
  short recruitZoneCount5c[6];
  short navySecondaryCount68; // 0x68 — navy secondary-order counter
  unsigned char pad6a[0x7c - 0x6a];
  unsigned char lowProductionFlag7c; // +0x7c — slot 0x0b
  unsigned char lowStockFlag7d;      // +0x7d — slot 0x0b
  // +0x7e..0xac — per-resource reserved amounts subtracted from the summary
  // (entry 0x13 doubles as the +0xa4 labor reserve in 0x004b44d0).
  short reservedByType7e[0x17];
  class TGreatPower* ownerNationAc; // 0xAC — owning nation state (0x004b4dc0)
  // +0xb0 — currently selected order; its +0x14 tile id drives the port-zone lookup
  void* selectedOrderB0; // +0xb0
  unsigned char pad_b4[0xB6 - 0xB4];
  // 0xB6..0xE4; fieldB6[0x15]/[0x16] occupy 0xE0/0xE2 (relationNeedSlotE0/E2).
  short fieldB6[0x17];
  // +0xe4..+0x1d8 — owned order objects, released through slot 0x1c on teardown.
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
  TPtrList* trackedOrderList270;     // 0x270 — released via FreePayloadsAndDestroySlot58
  class TQueueObject* eventQueue274; // 0x274 — released via Call24

  TCity(); // 0x004b24b0 ("InitializeCityModel")

  int GetBuildingProductionValueBySlot(short buildingSlot);

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
};

// === BEGIN GENERATED (TCity) — refreshed by `just gen-class TCity`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064f580 (33 slots), object size 0x2d4, base TObject
//   slot 0x00  byte 0x00  0x004b2490  new       GetTCityClassNamePointer
//   slot 0x01  byte 0x04  0x004b2520  new       VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004b35d0  new       SerializeCityProductionState
//   slot 0x06  byte 0x18  0x004b30a0  new       DeserializeCityProductionState
//   slot 0x07  byte 0x1c  0x004b3a60  new       Call1C
//   slot 0x08  byte 0x20  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004b3b40  new       OrphanCallChain_C13_I161_004b3b40
//   slot 0x0b  byte 0x2c  0x004b3de0  new       Call2C
//   slot 0x0c  byte 0x30  0x004b3e70  new       RefreshOrderStateSlot0C
//   slot 0x0d  byte 0x34  0x004b3fb0  new       AddNeedVectorSplitSlot34
//   slot 0x0e  byte 0x38  0x004b4090  new       AddOwnerNeedTargetsSlot38
//   slot 0x0f  byte 0x3c  0x004b4040  new       AddNeedVectorSlot3C
//   slot 0x10  byte 0x40  0x004b4580  new       CreateAltownCityObject
//   slot 0x11  byte 0x44  0x004b3b20  new       OrphanTiny_SetDwordEcxOffset_b0_004b3b20
//   slot 0x12  byte 0x48  0x004b4540  new       WriteQueuePairSlot48
//   slot 0x13  byte 0x4c  0x004b40e0  new       AllocateNeedFromOwnerSlot4C
//   slot 0x14  byte 0x50  0x004b46c0  new       OrphanLeaf_NoCall_Ins03_004b46c0
//   slot 0x15  byte 0x54  0x004b46e0  new       GetCityBuildingDisplayCapacityBySlot
//   slot 0x16  byte 0x58  0x004b48a0  new       GetBuildingCapacityTierSlot58
//   slot 0x17  byte 0x5c  0x004b4940  new       WrapperFor_GetActiveNationId_At004b4940
//   slot 0x18  byte 0x60  0x004b4d50  new       ToggleCityPowerPlantUpgradeOrder
//   slot 0x19  byte 0x64  0x004b4c80  new       OrphanLeaf_NoCall_Ins08_004b4c80
//   slot 0x1a  byte 0x68  0x004b4cc0  new       OrphanLeaf_NoCall_Ins11_004b4cc0
//   slot 0x1b  byte 0x6c  0x004b4230  new       OrphanLeaf_NoCall_Ins07_004b4230
//   slot 0x1c  byte 0x70  0x004b4260  new       OrphanLeaf_NoCall_Ins04_004b4260
//   slot 0x1d  byte 0x74  0x004b44d0  new       GetCitySummaryRecordSlot74
//   slot 0x1e  byte 0x78  0x004b4d00  new       IsBasicResourceSlot78
//   slot 0x1f  byte 0x7c  0x004b4210  new       OrphanRetStub_004b4210
//   slot 0x20  byte 0x80  0x004b4180  new       Refresh80
// object size 0x2d4 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCity) ===
