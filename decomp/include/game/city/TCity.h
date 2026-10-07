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

// The per-nation city and production model (TGreatPower::city).
// LAYOUT: RECOVERED
// VTABLE: IMPERIALISM 0x0064f580
class TCity : public TObject {
public:
  DECLARE_DYNCREATE(TCity)
  ~TCity() override;

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  virtual void EndCityPhase();
  virtual void PredictedNeeds();
  virtual void ProduceUnits();
  virtual void AddPurchasedItems(short* needVector);
  virtual void AddTransportedItems(short* amounts);
  virtual void AddTransportedItems();
  virtual void MakeTown(short selectedResourceType);
  virtual void SetSelectedTownMarker(TTown* townMarker);
  virtual void AddTransportRequest(short low, short high);
  virtual short DirectTransport(short needIndex, short amount);
  virtual void TransferTransportRequests();
  virtual short GetMaxBuildingCapacity(int buildingSlot);
  virtual char GetNextBuildingLevel(int buildingSlot);
  virtual short GetNextBuildingType(short buildingSlot);
  virtual void BuildPowerPlant(bool enableUpgrade);
  virtual void SetBuildingWindowState(short productionSlot, bool flag, short current, short accum);
  virtual char GetBuildingWindowState(short productionSlot, short* outCurrent, short* outAccum);
  virtual int GetRollingStock();
  virtual void SetRollingStock(short value);
  virtual short* GetUnmetNeeds();
  virtual short IsCapacityCenter(short resourceSlot);
  virtual void MouseTrap();
  virtual void VerifyStocks();

  int PickRandomMerchantVictims(short maxWeight, short* outCounts);

  int GetMerchantMarineDeciSpeed();
  int GetMerchantMarineAverageCargoHold();

  bool powerPlantUpgradeQueuedFlag; // BuildPowerPlant queue flag
  unsigned char pad05;
  short foodSubstitutionCount;    // workers reassigned after food substitution
  short starvationPopulationLoss; // population lost during the last Eat pass
  short serializedState;
  short cityPhaseCounter;
  short militaryRecruitCountByKind[kMilitaryUnitKindCount];
  short civilianRecruitCountByKind[kCivilianUnitKindCount];
  short orderCountByType[kIndustryActionSlotCount];
  int rollingItemProductionScore;
  bool lowProductionFlag; // PredictedNeeds
  bool lowStockFlag;      // PredictedNeeds
  short reservedByType[kResourceKindCount];
  class TGreatPower* ownerNation; // owning nation state
  TTown* homeTownMarker;
  short powerAvailable;
  short stockByType[kResourceKindCount];
  TProductionOrder* orderSlots[0x19];
  TUnitOrder* buildOrderSlots[0x12];
  TShipOrder* shipOrderSlots[8];
  TProductionOrder* trailingOrderSlots[0x0a];
  TPopulationMgr* productionSummary; // city population / summary
  short productionOrderTable[0x10];
  short productionAccum[0x10];         // ctor-cleared
  unsigned char productionFlags[0x10]; // ctor-cleared
  short production22c[0x10];           // GetBuildingWindowState outCurrent
  short production24c[0x10];           // GetBuildingWindowState outAccum
  short populationGrowthPenaltyTicks;  // GrowthRate penalty counter
  short pad26e;
  TTaskList* trackedOrderList; // released via FreeList
  class TPtrList* eventQueue;
  short unmetResourceRetryCount[kResourceKindCount];
  short consumedProductionInputByType[kResourceKindCount];

  TCity(); // 0x004b24b0 ("InitializeCityModel")

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
