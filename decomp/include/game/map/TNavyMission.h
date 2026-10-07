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
  TZone* missionTargetZone;
  TZone* resolvedPortZone;
  TShip* selectedOrder;              // +0x1c selected primary navy-order node
  TTaskForce* taskForce;             // +0x20 combined task-force/map-order entry
  TMapOrderChildLinkNode* orderList; // head of child order-node chain

  TShip* PickBestShipForMissionType(int missionType) const;

  float ComputeSeaZoneImportance(TZone* zone);
  int navyState; // +0x28 target-selection state (0 -> zone18 active, 1..2 -> zone14)
  float requiredShipEquipageByCategory[4];

  TNavyMission() : TMission() {
    missionTargetZone = NULL;
    resolvedPortZone = NULL;
    selectedOrder = NULL;
    this->taskForce = NULL;
    orderList = NULL;
    navyState = 0;
    for (int i = 0; i < 4; ++i) {
      requiredShipEquipageByCategory[i] = 0.0f;
    }
  }

  TNavyMission(TZone* targetZone);

  // Inline so concrete navy-mission destructors collapse through the empty base chain.
  // FUNCTION: IMPERIALISM 0x00535590
  virtual ~TNavyMission() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void
  Free() override; // slot 0x1c (TObject) 0x5364c0 -- releases orderList and deletes self

  virtual bool IsANoBrainer() const override;
  virtual int AccumulateLack(int* accumulatedLack, bool includeExistingLack)
      const override;                 // accumulates remaining ship-equipage lack
  virtual void Reassess() override;   // updates order-selection-mode state
  virtual void GiveOrders() override; // processes queued-order context mode
  virtual TMission* GetReplacement() override;
  virtual bool IsNavyMission() const override;
  virtual TMission* GetArmyMission() override; // returns null
  virtual TMission* GetNavyMission() override; // returns this
  virtual float GetWeightedSatisfaction() override;
  virtual float IndustrialCostOfNeeds() override;   // dot product with baseline profile
  virtual float ValueOf(TShip* candidate) override; // match delta vs candidate navy order
  virtual float FitnessOf(TShip* candidate,
                          float* targetProfile) override; // order penalty vs target profile
  virtual void AcceptReenforcement(TShip* item,
                                   bool notify) override; // attach order child and notify
  virtual void RejectConstituent(TShip* item,
                                 bool notify) override;         // detach and clear primary
  virtual void ForgetTaskForce(TTaskForce* taskForce) override; // clear secondary order if match
  virtual bool
  SmokeEmIfYouGotEm() override; // clears queued order links/owner pointers, returns true

  virtual void GiveActionOrders(TTaskForce* mapOrderEntry);
  virtual TZone* PickAmassingZone();
  virtual void GiveTravelOrders(TZone* location);
  virtual void GiveReconOrders(TZone* location, TShip** selectedOrder);
  // Selects the active target zone from lifecycle state28 (0 -> zone18, 1..2 -> zone14).
  virtual TZone* GetActiveTargetZone() const;

  void CombineForce(TZone* location, TTaskForce*& taskForce);

  void AccumulateShipEquipage(TShip* ship, float* vector, char positive);

  static float ScoreNationMatch(int sourceNation, TZone* nodeContext);
  static float ScoreEnemyMatch(int sourceNation, TZone* nodeContext);
  float ScoreZoneMatch(TZone* nodeContext);
  float ScoreZoneBaseMatch(TZone* nodeContext);
  float GetWeightedSatifactionWith(TShip* candidateOrder);
  float GetWeightedSatifactionWithout(TShip* candidateOrder);
  float ScorePortDefense(TZone* portZone);
  void ProjectEquipage(float* vector, TZone* nearZone, short distanceThreshold, TZone* farZone);
  void BuildMissionQueuedOrderCategoryVector(float* vector);
  float ProjectSatisfaction(short distanceThreshold);
};

ASSERT_SIZE(TNavyMission, 0x3c);
