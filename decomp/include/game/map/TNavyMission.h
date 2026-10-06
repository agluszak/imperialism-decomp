#pragma once

#include "game/map/TMission.h"
#include "game/navy/TTaskForce.h"

class TZone;
class TList;
class TShip;

// Navy-mission branch base (fills TMission abstract slots 0x27+; ctor 0x535470).
// VTABLE: IMPERIALISM 0x0065a818
class TNavyMission : public TMission {
  DECLARE_SERIAL(TNavyMission)
public:
  TZone* missionTargetZone;          // +0x14
  TZone* resolvedPortZone;           // +0x18
  TShip* selectedOrder1c;            // +0x1c selected primary navy-order node
  TTaskForce* taskForce20;           // +0x20 combined task-force/map-order entry
  TMapOrderChildLinkNode* orderList; // +0x24 -- head of child order-node chain

  TShip* PickBestShipForMissionType(int missionType) const;

  float ComputeSeaZoneImportance(TZone* zone);
  int navyState; // +0x28 target-selection state (0 -> zone18 active, 1..2 -> zone14)
  float requiredShipEquipageByCategory[4]; // +0x2c

  TNavyMission() : TMission() {
    missionTargetZone = nullptr;
    resolvedPortZone = nullptr;
    selectedOrder1c = nullptr;
    taskForce20 = nullptr;
    orderList = nullptr;
    navyState = 0;
    for (int i = 0; i < 4; ++i) {
      requiredShipEquipageByCategory[i] = 0.0f;
    }
  }

  TNavyMission(TZone* targetZone);

  // Inline so concrete navy-mission destructors collapse through the empty base chain.
  // FUNCTION: IMPERIALISM 0x00535590
  virtual ~TNavyMission() override {}
  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06
  virtual void
  Free() override; // slot 0x1c (TObject) 0x5364c0 -- releases orderList and deletes self

  virtual bool IsANoBrainer() const override; // slot 0x28 0x535500
  virtual int AccumulateLack(int* accumulatedLack, bool includeExistingLack)
      const override; // slot 0x2c 0x536840 -- accumulates remaining ship-equipage lack
  virtual void Reassess() override;   // slot 0x40 0x536b30 -- updates order-selection-mode state
  virtual void GiveOrders() override; // slot 0x44 0x536e40 -- processes queued-order context mode
  virtual TMission* GetReplacement() override;      // slot 0x48 0x536fc0
  virtual bool IsNavyMission() const override;      // slot 0x54 0x5354e0
  virtual TMission* GetArmyMission() override;      // slot 0x58 0x535520 -- returns null
  virtual TMission* GetNavyMission() override;      // slot 0x5c 0x535540 -- returns this
  virtual float GetWeightedSatisfaction() override; // slot 0x68 0x537f40
  virtual float
  IndustrialCostOfNeeds() override; // slot 0x6c 0x5378c0 -- dot product with baseline profile
  virtual float
  ValueOf(TShip* candidate) override; // slot 0x74 0x537270 -- match delta vs candidate navy order
  virtual float
  FitnessOf(TShip* candidate,
            float* targetProfile) override; // slot 0x7c 0x537610 -- order penalty vs target profile
  virtual void
  AcceptReenforcement(TShip* ship,
                      bool notify) override; // slot 0x84 0x536780 -- attach order child and notify
  virtual void
  RejectConstituent(TShip* ship,
                    bool notify) override; // slot 0x8c 0x5367d0 -- detach and clear primary
  virtual void ForgetTaskForce(
      TTaskForce* taskForce) override; // slot 0x90 0x536810 -- clear secondary order if match
  virtual char SmokeEmIfYouGotEm()
      override; // slot 0x98 0x536740 -- clears queued order links/owner pointers, returns true

  virtual void GiveActionOrders(TTaskForce* mapOrderEntry); // slot 0x27 0x5354c0
  virtual TZone* RefreshMissionPortZoneContextForNation();  // slot 0x28 0x536fa0
  virtual void
  ConsolidateMissionOrderEntriesByTargetAndQueue(TZone* location); // slot 0x29 0x5371d0
  virtual void GiveReconOrders(TZone* location,
                               TShip** selectedOrder); // slot 0x2a 0x537090
  // Selects the active target zone from lifecycle state28 (0 -> zone18, 1..2 -> zone14).
  virtual TZone* GetActiveTargetZoneByState28() const; // slot 0x2b 0x537060

  void CombineForce(TZone* location, TTaskForce*& taskForce); // 0x536d60

  void AccumulateWeightedShipEquipage(TShip* ship, float* vector, char positive);

  static float ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                           TZone* nodeContext);
  static float ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                          TZone* nodeContext);
  float ComputeOrderDistributionSimilarityScoreForZone(TZone* nodeContext);
  float ComputeOrderDistributionSimilarityScoreForZoneWithBaseProfile(TZone* nodeContext);
  float ComputeMissionOrderMatchScoreWithCandidateNavyOrder(TShip* candidateOrder);
  float ComputeMissionOrderMatchScoreWithScaledCandidateNavyOrder(TShip* candidateOrder);
  float ComputeMissionNavyOrderDistributionScoreForPortOwnerOrAllies(TZone* portZone);
  void ProjectEquipage(float* vector, TZone* nearZone, short distanceThreshold, TZone* farZone);
  void BuildMissionQueuedOrderCategoryVector(float* vector);
  float ProjectSatisfaction(short distanceThreshold);
};

ASSERT_SIZE(TNavyMission, 0x3c);
