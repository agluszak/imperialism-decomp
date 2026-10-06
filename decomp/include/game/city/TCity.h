#pragma once

#include <cstring>
#include "game/ui_tags_common.h"

#include "decomp_types.h"
#include "game/app/TObject.h"
#include "game/city/TPopulationMgr.h"
#include "game/city/TProductionOrder.h"
#include "game/civilian_domain_types.h"
#include "game/military_domain_types.h"
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

  virtual void EndCityPhase();
  virtual void PredictedNeeds();
  virtual void ProduceUnits();
  virtual void AddPurchasedItems(short* needVector);
  // slot 0x0f — body 0x004b4040: city stock counter += amounts[i]; clears E0/E2.
  virtual void AddTransportedItems(short* amounts);
  virtual void AddTransportedItems();
  virtual void MakeTown(short selectedResourceType);
  virtual void SetSelectedTownMarker(TTown* townMarker);
  virtual void AddTransportRequest(short low, short high);
  virtual short DirectTransport(short needIndex, short amount);
  // slot 0x14 — body 0x004b46c0: forward to queue274 slot 0x20.
  virtual void TransferTransportRequests();
  // slot 0x15 — body 0x004b46e0 (vtable stores direct body, not ILT 0x00407464).
  virtual short GetMaxBuildingCapacity(int buildingSlot);
  virtual char GetNextBuildingLevel(int buildingSlot);
  // slot 0x17 — body 0x004b4940. Mac oracle: GetNextBuildingType(short).
  virtual short GetNextBuildingType(short buildingSlot);
  // slot 0x18 — body 0x004b4d50 (vtable stores direct body, not ILT 0x0040494e).
  virtual void BuildPowerPlant(bool enableUpgrade);
  // slot 0x19 — body 0x004b4c80: write the production flag/current/accum for a slot.
  virtual void SetBuildingWindowState(short productionSlot, bool flag, short current, short accum);
  virtual char GetBuildingWindowState(short productionSlot, short* outCurrent, short* outAccum);
  // slot 0x1b — body 0x004b4230: owner transportCapacity (0 when unowned).
  virtual int GetOwnerNeedCapA6();
  // slot 0x1c — body 0x004b4260: set owner transportCapacity.
  virtual void SetOwnerNeedCapA6(short value);
  virtual short* GetUnmetNeeds();
  // slot 0x1e — body 0x004b4d00: true for the basic resource slots 0..6 and 0xb.
  virtual short IsCapacityCenter(short resourceSlot);
  // slot 0x1f — body 0x004b4210.
  virtual void MouseTrap();
  virtual void VerifyStocks();

  int AllocateRandomResourceCountsWithinWeightBudget(short maxWeight, short* outCounts);

  int ComputeAverageWeightWord1TimesTenFromResourceCounts();
  int ComputeAverageWeightWord0TimesTenFromResourceCounts();

  unsigned char powerPlantUpgradeQueuedFlag; // +0x04 — BuildPowerPlant queue flag
  unsigned char pad05;
  short foodSubstitutionCount06;    // +0x06 — workers reassigned after food substitution
  short starvationPopulationLoss08; // +0x08 — population lost during the last Eat pass
  short serializedState;
  short cityPhaseCounter;
  short militaryRecruitCountByKind[kMilitaryUnitKindCount];
  short civilianRecruitCountByKind[kCivilianUnitKindCount];
  short orderCountByType5c[kIndustryActionSlotCount];
  int rollingItemProductionScore;
  unsigned char lowProductionFlag; // +0x7c — PredictedNeeds
  unsigned char lowStockFlag;      // +0x7d — PredictedNeeds
  short reservedByType7e[kResourceKindCount];
  class TGreatPower* ownerNationAc; // 0xAC — owning nation state (0x004b4dc0)
  TTown* homeTownMarker;            // +0xb0
  short powerAvailable;
  short cityStockCotton;
  short cityStockWool;
  short cityStockTimber;
  short cityStockCoal;
  short cityStockIron;
  short cityStockHorses;
  short cityStockOil;
  short cityStockCannedFood;
  short cityStockFabric;
  short cityStockLumber;
  short cityStockPaper;
  short cityStockSteel;
  short cityStockFuel;
  short cityStockClothing;
  short cityStockFurniture;
  short cityStockHardware;
  short cityStockArms;
  short cityStockGrain;
  short cityStockFruit;
  short cityStockFish;
  short cityStockLivestock;
  short cityStockGems;
  short cityStockGold;
  TProductionOrder* orderSlots[0x19];         // +0xe4..+0x147
  TUnitOrder* buildOrderSlots[0x12];          // +0x148..+0x18f
  TShipOrder* shipOrderSlots[8];              // +0x190..+0x1af
  TProductionOrder* trailingOrderSlots[0x0a]; // +0x1b0..+0x1d7
  TPopulationMgr*
      productionSummary; // 0x1D8 — city population / summary (TPopulationMgr vtbl 0x64f9b0)
  short productionOrderTable1dc[0x10];
  short productionAccum[0x10];         // 0x1FC — ctor-cleared
  unsigned char productionFlags[0x10]; // 0x21C — ctor-cleared
  short production22c[0x10];           // 0x22C — GetBuildingWindowState outCurrent
  short production24c[0x10];           // 0x24C — GetBuildingWindowState outAccum
  short populationGrowthPenaltyTicks;  // 0x26C — GrowthRate penalty counter
  short pad26e;
  TTaskList* trackedOrderList; // 0x270 — released via FreePayloadsAndDestroy
  class TPtrList* eventQueue;
  short unmetResourceRetryCount[kResourceKindCount];
  short consumedProductionInputByType2a6[kResourceKindCount];

  TCity(); // 0x004b24b0 ("InitializeCityModel")

  short& CityStockByType(int index) {
    return (&cityStockCotton)[index];
  }
  short HomeTownTileId() const {
    if (homeTownMarker != 0) {
      short tileId;
      tileId = homeTownMarker->tileIndex;
      return tileId;
    }
    return 1;
  }

  int GetBuildingType(short buildingSlot);

  void ICity(TGreatPower* ownerNation);
};

ASSERT_SIZE(TCity, 0x2d4);
