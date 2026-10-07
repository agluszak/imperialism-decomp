#pragma once

#include "compat.h"

#include "game/city_ui/TInteriorMinister.h"
#include "game/resource_domain_types.h"

class TCity;
class TGreatPower;
class TLongintList;
class TList;
class TShortintList;
class TTaskList;
class TUnit;
class TFuzzySet;

// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TInteriorMinister {
public:
  // FUNCTION: IMPERIALISM 0x004be8b0
  virtual ~TCityInteriorMinister() override {}
  short GetRankingCriterionForGP(short nationSlot) override;
  virtual void MakeNewCity(TCity* city) override;
  virtual void FillOrders() override;
  virtual void PleaseBuildShip(short orderKind) override;
  virtual void IndustryOrder(short industrySlot) override;
  virtual void PleaseBuildLandUnit(short unitType) override;
  virtual short GetExteriorNeedFor(int resourceKind) override;
  virtual short GetHistoricalNeedFor(int resourceKind) override;
  virtual void ResetHistoricalNeedFor(int resourceKind) override;
  virtual void FillLists();
  virtual void DetermineTradeBid(TCity* city);
  virtual void IssueBasicOrders(TCity* city, TTaskList* commandQueue);
  virtual void OverstockCheck(TCity* city, TTaskList* commandQueue);
  virtual void NoOpProductionCommandHook24(int unusedArg1, int unusedArg2);
  virtual void TrainingMode(TCity* city, TTaskList* commandQueue);
  virtual void IncreaseCapacityMode(TCity* city, TTaskList* commandQueue);
  virtual void LandUnitMode(TCity* city, TTaskList* commandQueue);
  virtual void BuildMerchantShipMode(TCity* city, TTaskList* commandQueue);
  virtual void QueuePendingRecruitmentProductionCommand(TCity* city, TTaskList* commandQueue);
  virtual void QueuePendingUnitProductionCommand(TCity* city, TTaskList* commandQueue);
  virtual void IncreaseRailCapacityMode(TCity* city, TTaskList* commandQueue);
  virtual void DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(TCity* city);
  virtual void PleaseBuildCivilian(short commandIndex);
  virtual short AttemptTransport(short resourceType, short requestedAmount, short allocationLimit);
  virtual short DoTransport(TCity* city, TTaskList* commandQueue);
  virtual int SelectCitySite();
  virtual void RebuildMapTileNeighborBucketsForInteriorMinister();
  virtual void ShopForCivilians();
  virtual void ProspectAndDevelop();
  virtual void AutoAssignProspectingOrdersFromSeedTileNeighbors();
  virtual void ProcessUnitOrders();
  virtual void SeekLostTowns(char* primaryDistanceMap, char* secondaryDistanceMap);
  virtual void ContinueRailheadProject(TUnit* order, char* primaryDistanceMap,
                                       char* secondaryDistanceMap);
  virtual void StartRailheadProject(ResourceKindStorage resourceKind, TShortintList* ownedTiles,
                                    char* primaryDistanceMap, char* secondaryDistanceMap);
  virtual short EvaluateResources(short tileIndex);
  virtual int ScoreResource(int amount, int unusedResourceType,
                            int scorePerUnit); // Mac oracle name
  virtual char* CreateSeaDistanceMap(TShortintList* ownedTiles);
  virtual char* BuildFrogCityDistanceMapFromReachableSeaCandidates(TShortintList* ownedTiles);
  virtual void RebalanceCityOrderAllocationTargets(TCity* city);
  virtual void ProcessCityOrderStateTickAndApplyCapabilitySelection();
  virtual void RebalanceCitySupportAndLaborAllocations();
  virtual void ChooseAndMarkNextCityProductionCommand();
  virtual void ComputeCityProductionCommandLimitsFromBuildingOutputs();
  virtual void RebuildCityOrderCommandAvailabilityAndPriorityCycle();
  virtual void UpdateMinisterProductionMetricsForResourceIndex(short orderSlot);
  virtual short RequestLabor(short targetLabor);
  virtual void FillRemainingNeedCapacityAndReducePowerPlantOrder();
  virtual short RequestResource(short resourceType, short requestedAmount, short flags);
  virtual void SeekResources(TShortintList* ownedTiles, char* primaryDistanceMap);
  void DispatchBuilders();
  TCityInteriorMinister();
  void InitializeCityInteriorState(TGreatPower* owner);
  float GetAiDevelopmentResourceBudgetScale(int* resourcePools);
  int GetAverageDevelopmentOrderAllocation();
  bool AttemptUpgrade(short capabilitySlot);

  DECLARE_DYNCREATE(TCityInteriorMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  TLongintList* list28;
  TLongintList* list2c;                // +0x2c  (new TLongintList)
  short nextProductionBuildingOrdinal; // based cursor into list2c
  short pendingShipType;               // +0x32  ship type queued at city slot 0x2b
  short field34;
  short pendingRecruitmentCommandIndex; // +0x36  maps to city order slot 0x22 + value
  short pendingUnitCommandIndex;        // +0x38  maps to city order slot 0x19 + value
  short resource15ProductionPercent;    // +0x3a  init 50
  short railheadTargetTile;             // +0x3c  init -1
  short accumulatedUnmetNeed;           // +0x3e  queued via command 0x33
  short orderMetricTable[61];           // +0x40..0xba  (zeroed on init)
  short orderShortTableBA[16];
  short deferredLaborShortfall;
  short orderShortTableDC[16];
  short orderTypeTableFC[23];
  short exteriorNeedByType[23];   // +0x12a..0x158 (exterior need by order type)
  short historicalNeedByType[23]; // +0x158..0x186 (historical need by order type)
  short temporarilyReservedShipArms;
  TFuzzySet* cityPolicyFuzzySet; // +0x188 (new TFuzzySet, 4 policy curves)
  TList* orderList;              // +0x18c (new TList; ctor 0x4be840 nulls it)
  TLongintList* list190;         // +0x190 (new TLongintList)
  short civilianOrderDemandByResourceType[23];
  short temporaryFurnitureSubstituteLumber;

  short& LowSkillLaborShortfall() {
    return orderMetricTable[60];
  }
};
ASSERT_SIZE(TCityInteriorMinister, 0x1c4);
