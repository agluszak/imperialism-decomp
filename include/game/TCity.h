#pragma once

#include <cstring>

#include "decomp_types.h"
#include "game/TObject.h"
#include "game/TPopulationMgr.h"
#include "game/TProductionOrder.h"

class TSortedList;
class TStream;
class TShipOrder;
class TUnitOrder;

struct TCityTransportRequest {
  short resourceType;
  short requestedAmount;
};

ASSERT_SIZE(TCityTransportRequest, 0x04);

// The per-nation city/production model at TGreatPower+0x894 (field `city`).
// RTTI: g_pClassDescTCity @ 0x0064f338; CreateObject body at 0x004b2410.
// LAYOUT: RECOVERED
// VTABLE: IMPERIALISM 0x0064f580
class TCity : public TObject {
public:
  DECLARE_DYNCREATE(TCity)
  ~TCity() override;

  // slots 0x05–0x07 — TObject stream lifecycle (bodies 0x004b35d0 / 0x004b30a0 / 0x004b3a60).
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  // slot 0x0a — body 0x004b3b40 (528B, unported).
  virtual void EndCityPhase();
  // slot 0x0b — body 0x004b3de0: refresh the low-stock/low-summary flags and push
  // city stock counters to the owner (TGreatPower slot 0x3f).
  virtual void PredictedNeeds();
  // slot 0x0c — body 0x004b3e70: dispatch pending build/ship orders to the owner
  // (slot 0xb0) then tick every owned order object (vt+0x34).
  virtual void ProduceUnits();
  // slot 0x0d — body 0x004b3fb0: add a 17-entry need vector into the city stock block
  // (split 7/6/4 across the city stock block).
  virtual void AddPurchasedItems(short* needVector);
  // slot 0x0f — body 0x004b4040: city stock counter += amounts[i]; clears E0/E2.
  virtual void AddTransportedItems(short* amounts);
  // slot 0x0e — body 0x004b4090: city stock counter += owner->needTargetByType[i]; clears
  // E0/E2. MSVC500 emits overloaded virtuals in reverse declaration order — short*
  // must be declared before the no-arg overload to land in vtable slots 0x0f / 0x0e.
  virtual void AddTransportedItems();
  // slot 0x10 — body 0x004b4580 (247B, unported): create the Altown city object.
  virtual void MakeTown(short selectedResourceType);
  // slot 0x11 — body 0x004b3b20: adopt the selected order/marker (TGreatPower slots
  // 0x3a/0x3b hand the new Frog City marker through this).
  virtual void SetSelectedTownMarker(void* order);
  // slot 0x12 — body 0x004b4540: pack two shorts and write them to eventQueue274
  // (slot 0x38).
  virtual void AddTransportRequest(short low, short high);
  // slot 0x13 — body 0x004b40e0: allocate up to `amount` of a need from the owner's
  // current-over-target surplus (capped by needCapA6 - overCap), accumulate into
  // city stock and push the new target (TGreatPower slot 0x45).
  virtual short DirectTransport(short needIndex, short amount);
  // slot 0x14 — body 0x004b46c0: forward to queue274 slot 0x20.
  virtual void TransferTransportRequests(void* message = 0);
  // slot 0x15 — body 0x004b46e0 (vtable stores direct body, not ILT 0x00407464).
  virtual short GetMaxBuildingCapacity(int buildingSlot);
  // slot 0x16 — body 0x004b48a0: capacity tier (1..4) for a building slot, with the
  // tighter thresholds for slots 1/3/5.
  virtual char GetNextBuildingLevel(int buildingSlot);
  // slot 0x17 — body 0x004b4940 (577B, unported).
  virtual int GetActiveNationBuildingMetricSlot5C(short buildingSlot);
  // slot 0x18 — body 0x004b4d50 (vtable stores direct body, not ILT 0x0040494e).
  virtual void BuildPowerPlant(char enableUpgrade);
  // slot 0x19 — body 0x004b4c80: write the production flag/current/accum for a slot.
  virtual void SetBuildingWindowState(short productionSlot, char flag, short current, short accum);
  // slot 0x1a — body 0x004b4cc0: read the production flag byte (+0x21c) and the two
  // production shorts (+0x22c/+0x24c) for a slot.
  virtual char GetBuildingWindowState(short productionSlot, short* outCurrent, short* outAccum);
  // slot 0x1b — body 0x004b4230: owner needCapA6 (0 when unowned).
  virtual int GetOwnerNeedCapA6();
  // slot 0x1c — body 0x004b4260: set owner needCapA6.
  virtual void SetOwnerNeedCapA6(short value);
  // slot 0x1d — body 0x004b44d0: subtract the city's reserved amounts from the raw
  // summary array and return it (shorts at +0x22/+0x24/+0x28 summed by TGreatPower
  // slot 0x65, body 0x004dd7f0).
  virtual short* GetCitySummaryRecordSlot74();
  // slot 0x1e — body 0x004b4d00: true for the basic resource slots 0..6 and 0xb.
  virtual short IsCapacityCenter(short resourceSlot);
  // slot 0x1f — body 0x004b4210.
  virtual void MouseTrap();
  // slot 0x20 — body 0x004b4180: clamp negative city stock entries to 0 (asserting via
  // UCity.cpp:0x47f unless replaying).
  virtual void VerifyStocks();

  // 0x004b4390. Randomly draws resource units from this city's orderCountByType5c
  // counters (skipping types the RNG block-flag disables) until `maxWeight` of
  // resource weight has been allocated, tallying each drawn type into `outCounts` and
  // decrementing the city's counter. Returns the total allocated weight (capped at
  // `maxWeight`). Used by TNavyMgr::ProcessNationMapOrderInteractionsAndApplyOutcomes.
  int AllocateRandomResourceCountsWithinWeightBudget(short maxWeight, short* outCounts);

  // 0x004b4290 / 0x004b4310. Count-weighted average (x10) of each resource type's
  // descriptor weight word (1 / 0 respectively) across this city's orderCountByType5c
  // counters. Empty counters return 0 / 1.
  int ComputeAverageWeightWord1TimesTenFromResourceCounts();
  int ComputeAverageWeightWord0TimesTenFromResourceCounts();

  unsigned char powerPlantUpgradeQueuedFlag04; // +0x04 — BuildPowerPlant queue flag
  unsigned char pad05;
  short field06; // +0x06 — zeroed by the ctor
  short field08; // +0x08 — zeroed by the ctor
  short serializedState0a;
  short serializedState0c;
  // +0x0e..+0x4a and +0x4a..+0x5c — city metric blocks snapshotted wholesale by the
  // turn-event-0x2c composite packet (0x54ce80); interior meaning still unmapped.
  short cityMetricsBlock0E[0x1e];
  short cityMetricsBlock4A[9];
  // +0x5c..+0x78 — per-order/resource-type counters (one short per type 0..13):
  // the pending-action FSM (0x004dab20) bumps the active zone's entry and entry 6
  // (navy secondary orders); 0x004dd140 weights all 14 entries by the resource
  // descriptor to rebuild the diplomacy aid budget score.
  short orderCountByType5c[0x0e];
  int field78;                       // +0x78 — snapshotted by the turn-event-0x2c packet
  unsigned char lowProductionFlag7c; // +0x7c — PredictedNeeds
  unsigned char lowStockFlag7d;      // +0x7d — PredictedNeeds
  // +0x7e..0xac — per-resource reserved amounts subtracted from the summary
  // (entry 0x13 doubles as the +0xa4 labor reserve in 0x004b44d0).
  short reservedByType7e[0x17];
  class TGreatPower* ownerNationAc; // 0xAC — owning nation state (0x004b4dc0)
  // +0xb0 — currently selected order; its +0x14 tile id drives the port-zone lookup
  void* selectedOrderB0; // +0xb0
  // +0xB4 — city power value displayed by TWarehouseView's 'powe' control and
  // snapshotted by the turn-event-0x2c packet.
  short powerAvailableB4;
  // 0xB6..0xE4 — city commodity stock/need counters, commodity order:
  // Cotton..Gold (bitmap ids 700..722 / strings 17077..17099).
  short cityStockCottonB6;
  short cityStockWoolB8;
  short cityStockTimberBA;
  short cityStockCoalBC;
  short cityStockIronBE;
  short cityStockHorsesC0;
  short cityStockOilC2;
  short cityStockCannedFoodC4;
  short cityStockFabricC6;
  short cityStockLumberC8;
  short cityStockPaperCA;
  short cityStockSteelCC;
  short cityStockFuelCE;
  short cityStockClothingD0;
  short cityStockFurnitureD2;
  short cityStockHardwareD4;
  short cityStockArmsD6;
  short cityStockGrainD8;
  short cityStockFruitDA;
  short cityStockFishDC;
  short cityStockLivestockDE;
  short cityStockGemsE0;
  short cityStockGoldE2;
  // +0xe4..+0x1d8 — mixed city payload table (0x3d pointer slots).
  // Band boundaries traced from InitializeCityProductionState (0x004b2570):
  //   0x00..0x18 heterogeneous TItemOrder/TOrItemOrder (idx 0x08) plus
  //              TTrainingOrder (idx 0x07/0x17/0x18); all TProductionOrder-derived.
  //   0x19..0x2a TUnitOrder (build orders)
  //   0x2b..0x32 TShipOrder (navy orders, LEA [ESI+0x190] loop of 8)
  //   0x33..0x3c trailing band incl. TPowerPlantOrder (idx 0x34) and other
  //              TProductionOrder-derived slots; TRailAmtBar (0x0058a020)
  //              indexes across this band via tradeCommodityRecordPtrs
  //              (idx 0x33/0x34/0x3c), relying on same-type contiguity with
  //              trailingOrderSlots — kept flat-typed as TProductionOrder* so
  //              that cross-band indexing stays type-consistent.
  union {
    TProductionOrder* orderSlotsE4[0x3D];
    struct {
      TProductionOrder* tradeCommodityRecordPtrs[0x19]; // 0x00..0x18
      TUnitOrder* buildOrderSlots[0x12];                // 0x19..0x2a
      TShipOrder* shipOrderSlots[8];                    // 0x2b..0x32
      TProductionOrder* trailingOrderSlots[0x0a];       // 0x33..0x3c
    };
  };
  TPopulationMgr*
      productionSummary1d8; // 0x1D8 — city population / summary (TPopulationMgr vtbl 0x64f9b0)
  // 0x1DC — 16-entry per-city production order table (0x004b4dc0, ctor-cleared).
  short productionOrderTable1dc[0x10];
  short productionAccum1fc[0x10];         // 0x1FC — ctor-cleared
  unsigned char productionFlags21c[0x10]; // 0x21C — ctor-cleared
  short production22c[0x10];              // 0x22C — GetBuildingWindowState outCurrent
  short production24c[0x10];              // 0x24C — GetBuildingWindowState outAccum
  short field26c;                         // 0x26C — zeroed by the ctor
  short pad26e;
  TSortedList* trackedOrderList270; // 0x270 — released via FreePayloadsAndDestroy
  // 0x274 — TPtrList (vtable 0x649068, recordSize14 4; allocated in
  // InitializeCityProductionState 0x4b2dca); released via ReleasePtrList.
  class TPtrList* eventQueue274;
  // +0x278 — per-resource failed-request counters maintained by the interior
  // minister when a production sheet cannot be fully transported.
  short unmetResourceRetryCount278[0x17];
  // +0x2a6 — one short per resource type. Existing consumers use entries 13..16;
  // ReadFrom/WriteTo serialize and byte-swap all 23 entries as one array.
  short consumedProductionInputByType2a6[0x17];

  TCity(); // 0x004b24b0 ("InitializeCityModel")

  short& CityStockByType(int index) {
    return (&cityStockCottonB6)[index];
  }
  // Marker-less accessor: the original inlines this at every call site, so it must
  // be defined in the header to inline across translation units under MSVC500.
  short SelectedOrderTileId() const {
    if (selectedOrderB0 != 0) {
      short tileId;
      const char* marker = static_cast<const char*>(selectedOrderB0);
      memcpy(&tileId, marker + 0x14, sizeof(tileId));
      return tileId;
    }
    return 1;
  }

  int GetBuildingType(short buildingSlot);

  // 0x004b2570: initialize production arrays and build the city entry-object tables.
  void InitializeCityProductionState(TGreatPower* ownerNation);
};

ASSERT_SIZE(TCity, 0x2d4);
