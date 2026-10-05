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
  virtual ~TCityInteriorMinister() override {} // slot 0x01 (scalar deleting destructor)
  short GetRankingCriterionForGP(short nationSlot) override; // slot 0x0a 0x4bee20
  virtual void MakeNewCity(TCity* city) override;            // slot 0x11 0x4c0d90
  virtual void FillOrders() override;                        // slot 0x15 0x4bf770
  virtual void PleaseBuildShip(short arg) override;          // slot 0x1a 0x4beeb0
  virtual void IndustryOrder(short industrySlot) override;   // slot 0x1b 0x4beee0
  virtual void PleaseBuildLandUnit(short unitType) override; // slot 0x1c 0x4bef30
  virtual short GetExteriorNeedFor(int arg) override;        // slot 0x1d 0x4be7b0
  virtual short GetHistoricalNeedFor(int arg) override;      // slot 0x1e 0x4be7d0
  virtual void ResetHistoricalNeedFor(int arg) override;     // slot 0x1f 0x4be7f0
  virtual void FillLists();                                  // slot 0x20 0x4bed60
  virtual void DetermineTradeBid(TCity* city); // slot 0x21 0x4bf8a0
  virtual void IssueBasicOrders(TCity* city,
                                TTaskList* commandQueue); // slot 0x22 0x4bfa50
  virtual void OverstockCheck(TCity* city,
                              TTaskList* commandQueue); // slot 0x23 0x4bfb20
  virtual void NoOpProductionCommandHook24(int unusedArg1, int unusedArg2); // slot 0x24 0x4bff60
  virtual void TrainingMode(TCity* city, TTaskList* commandQueue);          // slot 0x25 0x4c02c0
  virtual void IncreaseCapacityMode(TCity* city,
                                    TTaskList* commandQueue);      // slot 0x26 0x4c0090
  virtual void LandUnitMode(TCity* city, TTaskList* commandQueue); // slot 0x27 0x4c04e0
  virtual void BuildMerchantShipMode(TCity* city,
                                     TTaskList* commandQueue); // slot 0x28 0x4c05a0
  virtual void
  QueuePendingRecruitmentProductionCommand(TCity* city,
                                           TTaskList* commandQueue); // slot 0x29 0x4c0690
  virtual void QueuePendingUnitProductionCommand(TCity* city,
                                                 TTaskList* commandQueue); // slot 0x2a 0x4c0730
  virtual void IncreaseRailCapacityMode(TCity* city,
                                        TTaskList* commandQueue); // slot 0x2b 0x4bff80
  virtual void DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(
      TCity* city);                                     // slot 0x2c 0x4c07d0
  virtual void PleaseBuildCivilian(short commandIndex); // slot 0x2d 0x4bef10
  virtual short AttemptTransport(short resourceType, short requestedAmount,
                                                      short allocationLimit); // slot 0x2e 0x4c0de0
  virtual short
  RebuildNeedTargetsAndQueueProductionShortfalls(TCity* city,
                                                 TTaskList* commandQueue); // slot 0x2f 0x4c0e50
  virtual int SelectBestSecondaryHomeTileByFrogCityScore();        // slot 0x30 0x4c11c0
  virtual void RebuildMapTileNeighborBucketsForInteriorMinister(); // slot 0x31 0x4c1ac0
  virtual void RequestMissingCivilianOrderTypes();                 // slot 0x32 0x4c2010
  virtual void AutoAssignProspectingOrdersByTileHeuristics();      // slot 0x33 0x4c2120
  virtual void AutoAssignProspectingOrdersFromSeedTileNeighbors(); // slot 0x34 0x4c2a30
  virtual void ProcessUnitOrders();                                // slot 0x35 0x4c1510; Mac oracle
  virtual void SeekLostTowns(char* primaryDistanceMap,
                             char* secondaryDistanceMap); // slot 0x36 0x4c2d50
  virtual void ContinueRailheadProject(TUnit* order, char* primaryDistanceMap,
                                       char* secondaryDistanceMap); // slot 0x37 0x4c2e10
  virtual void StartRailheadProject(ResourceKindStorage resourceKind, TShortintList* ownedTiles,
                                    char* primaryDistanceMap,
                                    char* secondaryDistanceMap); // slot 0x38 0x4c3170
  virtual short EvaluateResources(short tileIndex);              // slot 0x39 0x4c3490
  virtual int ScoreResource(int amount, int unusedResourceType,
                            int scorePerUnit); // slot 0x3a 0x4c3620; Mac oracle name
  virtual char* CreateSeaDistanceMap(TShortintList* ownedTiles); // slot 0x3b 0x4c3640
  virtual char*
  BuildFrogCityDistanceMapFromReachableSeaCandidates(TShortintList* ownedTiles); // slot 0x3c
                                                                                 // 0x4c3910
  virtual void RebalanceCityOrderAllocationTargets(TCity* city);        // slot 0x3d 0x4c3c00
  virtual void ProcessCityOrderStateTickAndApplyCapabilitySelection();  // slot 0x3e 0x4c3d60
  virtual void RebalanceCitySupportAndLaborAllocations();               // slot 0x3f 0x4c40c0
  virtual void ChooseAndMarkNextCityProductionCommand();                // slot 0x40 0x4c4370
  virtual void ComputeCityProductionCommandLimitsFromBuildingOutputs(); // slot 0x41 0x4c4690
  virtual void RebuildCityOrderCommandAvailabilityAndPriorityCycle();   // slot 0x42 0x4c4840
  virtual void
  UpdateMinisterProductionMetricsForResourceIndex(short orderSlot);        // slot 0x43 0x4c49f0
  virtual short RaisePowerPlantOrderToReachLaborTarget(short targetLabor); // slot 0x44 0x4c4d40
  virtual void FillRemainingNeedCapacityAndReducePowerPlantOrder();        // slot 0x45 0x4c4e60
  virtual short RequestResource(short resourceType, short requestedAmount,
                                short flags); // slot 0x46 0x4c4fe0; Mac oracle
  virtual void SeekResources(TShortintList* ownedTiles,
                             char* primaryDistanceMap); // slot 0x47 0x4c5240
  void DispatchBuilders();                              // 0x4c1990
  TCityInteriorMinister();
  void InitializeCityInteriorState(TGreatPower* owner);
  float GetAiDevelopmentResourceBudgetScale(int* resourcePools);
  int GetAverageDevelopmentOrderAllocation();
  bool TryApplyCityOrderCapabilitySelectionBySlot(short capabilitySlot); // 0x004c56e0

  DECLARE_DYNCREATE(TCityInteriorMinister)
  void WriteTo(TStream* stream) override;  // slot 0x14
  void ReadFrom(TStream* stream) override; // slot 0x18
  void Free() override;                    // slot 0x1c

  TLongintList* list28;                 // +0x28  (new TLongintList, vtable 0x650a08)
  TLongintList* list2c;                 // +0x2c  (new TLongintList)
  short nextProductionBuildingOrdinal;  // +0x30  1-based cursor into list2c
  short pendingShipType32;              // +0x32  ship type queued at city slot 0x2b
  short field34;                        // +0x34
  short pendingRecruitmentCommandIndex; // +0x36  maps to city order slot 0x22 + value
  short pendingUnitCommandIndex;        // +0x38  maps to city order slot 0x19 + value
  short resource15ProductionPercent;    // +0x3a  init 50
  short field3c;                        // +0x3c  init -1
  short accumulatedUnmetNeed3e;         // +0x3e  queued via command 0x33
  short orderMetricTable40[61]; // +0x40..0xba  (zeroed on init)
  short orderShortTableBA[16];  // +0xba..0xda
  short deferredLaborShortfall; // +0xda
  short orderShortTableDC[16];  // +0xdc..0xfc
  short orderTypeTableFC[23];        // +0xfc..0x12a
  short orderTypeTable12A[23];       // +0x12a..0x158 (exterior need by order type)
  short orderTypeTable158[23];       // +0x158..0x186 (historical need by order type)
  short temporarilyReservedShipArms; // +0x186
  TFuzzySet* cityPolicyFuzzySet;     // +0x188 (new TFuzzySet, 4 policy curves)
  TList* orderList;                  // +0x18c (new TList; ctor 0x4be840 nulls it)
  TLongintList* list190;             // +0x190 (new TLongintList)
  short civilianOrderDemandByResourceType194[23]; // +0x194
  short temporaryFurnitureSubstituteLumber;       // +0x1c2

  short& LowSkillLaborShortfall() {
    return orderMetricTable40[60];
  }
};
ASSERT_SIZE(TCityInteriorMinister, 0x1c4);
