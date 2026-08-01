#pragma once

#include <cstring>
#include "game/ui_tags_common.h"

#include "decomp_types.h"
#include "game/app/TObject.h"
#include "game/city/TPopulationMgr.h"
#include "game/city/TProductionOrder.h"
#include "game/resource_domain_types.h"
#include "game/city/TTown.h"

class TSortedList;
class TTaskList;
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

  // slot 0x0a — body 0x004b3b40: settle city production, restock order sheets,
  // refresh population production state, and publish the resulting UI state.
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
  // slot 0x10 — body 0x004b4580: create the Altown city object. The selected
  // resource type is passed by the railhead dialog but unused by the retail body.
  virtual void MakeTown(short selectedResourceType);
  // slot 0x11 — body 0x004b3b20: adopt the selected order/marker (TGreatPower slots
  // 0x3a/0x3b hand the new Frog City marker through this).
  virtual void SetSelectedTownMarker(TTown* townMarker);
  // slot 0x12 — body 0x004b4540: pack two shorts and write them to eventQueue274
  // (slot 0x38).
  virtual void AddTransportRequest(short low, short high);
  // slot 0x13 — body 0x004b40e0: allocate up to `amount` of a need from the owner's
  // current-over-target surplus (capped by transportCapacity - overCap), accumulate into
  // city stock and push the new target (TGreatPower slot 0x45).
  virtual short DirectTransport(short needIndex, short amount);
  // slot 0x14 — body 0x004b46c0: forward to queue274 slot 0x20.
  virtual void TransferTransportRequests(void* message = 0);
  // slot 0x15 — body 0x004b46e0 (vtable stores direct body, not ILT 0x00407464).
  virtual short GetMaxBuildingCapacity(int buildingSlot);
  // slot 0x16 — body 0x004b48a0: capacity tier (1..4) for a building slot, with the
  // tighter thresholds for slots 1/3/5.
  virtual char GetNextBuildingLevel(int buildingSlot);
  // slot 0x17 — body 0x004b4940. Mac oracle: GetNextBuildingType(short).
  virtual short GetNextBuildingType(short buildingSlot);
  // slot 0x18 — body 0x004b4d50 (vtable stores direct body, not ILT 0x0040494e).
  virtual void BuildPowerPlant(char enableUpgrade);
  // slot 0x19 — body 0x004b4c80: write the production flag/current/accum for a slot.
  virtual void SetBuildingWindowState(short productionSlot, char flag, short current, short accum);
  // slot 0x1a — body 0x004b4cc0: read the production flag byte (+0x21c) and the two
  // production shorts (+0x22c/+0x24c) for a slot.
  virtual char GetBuildingWindowState(short productionSlot, short* outCurrent, short* outAccum);
  // slot 0x1b — body 0x004b4230: owner transportCapacity (0 when unowned).
  virtual int GetOwnerNeedCapA6();
  // slot 0x1c — body 0x004b4260: set owner transportCapacity.
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
  short foodSubstitutionCount06;    // +0x06 — workers reassigned after food substitution
  short starvationPopulationLoss08; // +0x08 — population lost during the last Eat pass
  short serializedState0a;
  short cityPhaseCounter0c;
  // +0x0e..+0x4a and +0x4a..+0x5c — city metric blocks snapshotted wholesale by the
  // turn-event-0x2c composite packet (0x54ce80); interior meaning still unmapped.
  short cityMetricsBlock0E[0x1e];
  short cityMetricsBlock4A[9];
  // +0x5c..+0x78 — per-order/resource-type counters (one short per type 0..13):
  // the pending-action FSM (0x004dab20) bumps the active zone's entry and entry 6
  // (navy secondary orders); 0x004dd140 weights all 14 entries by the resource
  // descriptor to rebuild the diplomacy aid budget score.
  short orderCountByType5c[0x0e];
  // +0x78 — exponentially decayed item-production activity. TItemOrder::Produce
  // accumulates completed quantities here; EndCityPhase applies old*0.9 + new*10.
  int rollingItemProductionScore78;
  unsigned char lowProductionFlag7c; // +0x7c — PredictedNeeds
  unsigned char lowStockFlag7d;      // +0x7d — PredictedNeeds
  // +0x7e..0xac — per-resource reserved amounts subtracted from the summary
  // (entry 0x13 doubles as the +0xa4 labor reserve in 0x004b44d0).
  short reservedByType7e[kResourceKindCount];
  class TGreatPower* ownerNationAc; // 0xAC — owning nation state (0x004b4dc0)
  // +0xb0 — the city's home TTown marker, and only ever that one type
  // (bd imperialism-decomp-i0in). The conflicting reading this slot used to carry --
  // that TGreatPower::SetHomeCityTileAndDisplayName (0x4dfd30) called
  // TProductionOrder::Restock through it -- was a mis-modelled call. That call passes one
  // LPCSTR argument, which Restock() cannot take; vtable slot 0x0e on TTown is
  // SetName(const char*) at 0x5b77e0, reached through ILT thunk 0x408acb. The slot number
  // merely coincided between the two classes.
  // The town marker occupying this city's tile -- the city's harvesting agent, not a
  // second city. See TTown.h for the one-city/many-towns relationship.
  TTown* homeTownMarkerB0; // +0xb0
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
  // +0xe4..+0x1d8 — city production-order fields (0x3d pointer slots).
  // Band boundaries traced from ICity (0x004b2570):
  //   0x00..0x18 heterogeneous TItemOrder/TOrItemOrder (idx 0x08) plus
  //              TTrainingOrder (idx 0x07/0x17/0x18); all TProductionOrder-derived.
  //   0x19..0x2a TUnitOrder (build orders)
  //   0x2b..0x32 TShipOrder (navy orders, LEA [ESI+0x190] loop of 8)
  //   0x33..0x3c trailing TProductionOrder-derived slots, including the power plant
  //              order at 0x34.
  TProductionOrder* orderSlotsE4[0x19];          // +0xe4..+0x147
  TUnitOrder* buildOrderSlots148[0x12];          // +0x148..+0x18f
  TShipOrder* shipOrderSlots190[8];              // +0x190..+0x1af
  TProductionOrder* trailingOrderSlots1b0[0x0a]; // +0x1b0..+0x1d7
  TPopulationMgr*
      productionSummary1d8; // 0x1D8 — city population / summary (TPopulationMgr vtbl 0x64f9b0)
  // 0x1DC — 16-entry per-city production order table (0x004b4dc0, ctor-cleared).
  short productionOrderTable1dc[0x10];
  short productionAccum1fc[0x10];         // 0x1FC — ctor-cleared
  unsigned char productionFlags21c[0x10]; // 0x21C — ctor-cleared
  short production22c[0x10];              // 0x22C — GetBuildingWindowState outCurrent
  short production24c[0x10];              // 0x24C — GetBuildingWindowState outAccum
  short populationGrowthPenaltyTicks26c;  // 0x26C — GrowthRate penalty counter
  short pad26e;
  TTaskList* trackedOrderList270; // 0x270 — released via FreePayloadsAndDestroy
  // 0x274 — TPtrList (vtable 0x649068, recordSize14 4; allocated in
  // ICity 0x4b2dca); released via ReleasePtrList.
  class TPtrList* eventQueue274;
  // +0x278 — per-resource failed-request counters maintained by the interior
  // minister when a production sheet cannot be fully transported.
  short unmetResourceRetryCount278[kResourceKindCount];
  // +0x2a6 — one short per resource type. Existing consumers use entries 13..16;
  // ReadFrom/WriteTo serialize and byte-swap all 23 entries as one array.
  short consumedProductionInputByType2a6[kResourceKindCount];

  TCity(); // 0x004b24b0 ("InitializeCityModel")

  short& CityStockByType(int index) {
    return (&cityStockCottonB6)[index];
  }
  // Marker-less accessor: the original inlines this at every call site, so it must
  // be defined in the header to inline across translation units under MSVC500.
  short HomeTownTileId() const {
    if (homeTownMarkerB0 != 0) {
      short tileId;
      tileId = homeTownMarkerB0->tileIndex;
      return tileId;
    }
    return 1;
  }

  int GetBuildingType(short buildingSlot);

  // 0x004b2570: initialize production arrays and build the city entry-object tables.
  void ICity(TGreatPower* ownerNation);
};

ASSERT_SIZE(TCity, 0x2d4);
