#pragma once

#include "game/TMission.h"
#include "game/TTaskForce.h"

class TZone;
class TList;
class TShip;

// Navy-mission branch base (fills TMission abstract slots 0x27+; ctor 0x535470).
// VTABLE: IMPERIALISM 0x0065a818
class TNavyMission : public TMission {
  DECLARE_SERIAL(TNavyMission)
public:
  TZone* targetZone14;                 // +0x14
  TZone* targetZone18;                 // +0x18
  TShip* selectedOrder1c;              // +0x1c selected primary navy-order node
  TTaskForce* taskForce20;             // +0x20 combined task-force/map-order entry
  TMapOrderChildLinkNode* orderList24; // +0x24 -- head of child order-node chain
  int navyState28; // +0x28 target-selection state (0 -> zone18 active, 1..2 -> zone14)
  float requiredShipEquipageByCategory[4]; // +0x2c

  TNavyMission();
  TNavyMission(TZone* targetZone);

  virtual ~TNavyMission() override;                // slot 0x01 dtor 0x535590 / ??_G 0x535560
  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06
  virtual void
  Free() override; // slot 0x1c (TObject) 0x5364c0 -- releases orderList24 and deletes self

  virtual char IsANoBrainer() const override; // slot 0x28 0x535500
  virtual int AccumulateLack(int* accumulatedLack, unsigned char includeExistingLack)
      const override; // slot 0x2c 0x536840 -- accumulates remaining ship-equipage lack
  virtual void Reassess() override;   // slot 0x40 0x536b30 -- updates order-selection-mode state
  virtual void GiveOrders() override; // slot 0x44 0x536e40 -- processes queued-order context mode
  virtual TMission* GetReplacementSlot48() override; // slot 0x48 0x536fc0
  virtual char IsNavyMission() const override;       // slot 0x54 0x5354e0
  virtual TMission* GetArmyMission() override;       // slot 0x58 0x535520 -- returns null
  virtual TMission* GetNavyMission() override;       // slot 0x5c 0x535540 -- returns this
  virtual float ReturnZeroFloatSlot68() override;    // slot 0x68 0x537f40
  virtual float
  ReturnZeroFloatSlot6C() override; // slot 0x6c 0x5378c0 -- dot product with baseline profile
  virtual float ReturnZeroFloatSlot74(
      void* candidate) override; // slot 0x74 0x537270 -- match delta vs candidate navy order
  virtual float ReturnZeroFloatSlot7C(
      void* candidate,
      void* targetProfile) override; // slot 0x7c 0x537610 -- order penalty vs target profile
  virtual void
  NoOpSlot84(void* a,
             int b) override; // slot 0x84 0x536780 -- attach order child as queued and notify
  virtual void
  NoOpSlot8C(void* a,
             int b) override; // slot 0x8c 0x5367d0 -- detach order child, clear primary if match
  virtual void NoOpSlot90(void* a) override; // slot 0x90 0x536810 -- clear secondary order if match
  virtual char ReturnFalseSlot98()
      override; // slot 0x98 0x536740 -- clears queued order links/owner pointers, returns true

  // TNavyMission-introduced virtuals (TMission abstract slots 0x27+ / offset 0x9c+).
  // Mac: GiveActionOrders(TTaskForce*). The base is a no-op; concrete missions use the
  // task-force/map-order entry passed by GiveOrders (taskForce20).
  virtual void GiveActionOrders(TTaskForce* mapOrderEntry); // slot 0x27 0x5354c0
  // Returns the best neighbor port zone for the current nation (delegates to
  // targetZone14->SelectBestPrimaryNeighborForNationDiplomacyMask); every override
  // (TControlSeaZoneMission/TScatteredShipsMission) also returns a TZone*, and
  // TControlSeaZoneMission::GetReplacementSlot48 consumes the caller's result, so this
  // could not stay void (confirmed by 0x538900's disassembly storing EAX back into
  // targetZone18).
  virtual TZone* RefreshMissionPortZoneContextForNation(); // slot 0x28 0x536fa0
  virtual void
  ConsolidateMissionOrderEntriesByTargetAndQueue(TZone* contextAnchor); // slot 0x29 0x5371d0
  virtual void QueueMissionOrdersByPriorityForContext(TZone* contextAnchor,
                                                      TShip** selectedOrder); // slot 0x2a 0x537090
  // Selects the active target zone from lifecycle state28 (0 -> zone18, 1..2 -> zone14).
  virtual TZone* GetActiveTargetZoneByState28() const; // slot 0x2b 0x537060

  // Mac: CombineForce(TZone*, TTaskForce*&). Reuses or creates the task force for
  // `contextAnchor`, then moves every matching mission order into it.
  void CombineForce(TZone* contextAnchor, TTaskForce*& taskForce); // 0x536d60

  static float ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                           TZone* nodeContext);
  static float ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                          TZone* nodeContext);
  // Instance form of the diplomacy-filtered scorer above: sources the filter's source
  // nation from this->nationId04 instead of taking it as an explicit argument, and
  // scores against g_Populate_Beachhead_Mission_LookupTable_00697958[4..7] instead of
  // [0..3]. 0x539a90.
  float ComputeOrderDistributionSimilarityScoreForZone(TZone* nodeContext);
  // Same shape as ComputeOrderDistributionSimilarityScoreForZone but scores against
  // g_Populate_Beachhead_Mission_LookupTable_00697958[0..3] (the same table/slice
  // NormalizeFourComponentNavyVector's other callers use). 0x538dd0.
  float ComputeOrderDistributionSimilarityScoreForZoneWithBaseProfile(TZone* nodeContext);
  // Builds a 4-category priority vector from every existing orderList24 ship plus
  // `candidateOrder` (each contribution weighted by a per-ship distance-decay factor,
  // see g_MissionOrderDistanceDecayWeightTable_006978c8), then scores it against
  // requiredShipEquipageByCategory via a Bhattacharyya-coefficient-style similarity:
  // sum(sqrt(requiredShipEquipageByCategory[i] * vector[i])) / sum(requiredShipEquipageByCategory[i]). Used to
  // evaluate how well adding `candidateOrder` would fit this mission's target profile.
  // 0x538120.
  float ComputeMissionOrderMatchScoreWithCandidateNavyOrder(TShip* candidateOrder);
  // Same shape as ComputeMissionOrderMatchScoreWithCandidateNavyOrder, but negates the
  // candidate ship's distance-weighted contribution (scale * -1.0) before accumulating
  // it -- evaluating the profile with the candidate order REMOVED rather than added.
  // 0x5383f0.
  float ComputeMissionOrderMatchScoreWithScaledCandidateNavyOrder(TShip* candidateOrder);
  // If `portZone` has a definite single owner nation (owner code 0..6), returns
  // ComputeNavyOrderDistributionScoreForNation-equivalent score for that owner directly.
  // Otherwise (owner code >= 7, no clear single owner) scans nations allied with this
  // mission's own nationId04 and takes the best such score -- though each iteration
  // re-reads portZone's (still out-of-range) owner code as the ship filter rather than
  // the candidate ally's index, so in practice this branch only ever contributes 0 (no
  // ship's ownerNationSlot14 can equal an out-of-range code); modeled exactly as observed
  // rather than "corrected", per Hard Rule 6. 0x53b350.
  float ComputeMissionNavyOrderDistributionScoreForPortOwnerOrAllies(TZone* portZone);
  // Builds a per-category priority vector over every orderList24 ship: a ship counts if
  // it's within `distanceThreshold` hops of `nearZone` (or unconditionally if `nearZone`
  // is null), OR (when farther than that) if it's within `distanceThreshold` hops of
  // `farZone` instead (when farZone is non-null and != nearZone).
  // 0x537900.
  void BuildNavyOrderCategoryVectorForNationWithExclusion(float* vector, TZone* nearZone,
                                                          short distanceThreshold, TZone* farZone);
  // Builds a per-category priority vector over every orderList24 ship, each weighted by
  // (stockLevel1c/normalizationBase) * a distance-decay factor (0.8^hopDistance to the
  // active target zone, clamped to index 5) -- same per-ship math as
  // AccumulateNavyOrderCategoryVectorWithScale, but the original inlines its own copy here
  // rather than calling out to 0x537c60, so the body is reproduced inline to match. 0x537d40.
  void BuildMissionQueuedOrderCategoryVector(float* vector);
  // Same shape as ComputeNavyOrderCategorySimilarityRatio (BuildNavyOrderCategoryVectorFor-
  // NationWithExclusion + a sqrt-coefficient tail), but always uses targetZone14 as the near
  // zone and targetZone18 as the far zone, with an explicit caller-
  // supplied distance threshold instead of a fixed 0/1. 0x537eb0.
  float ComputeMissionQueuedOrderSimilarityForTargetNation(short distanceThreshold);

private:
  // Shared by Reassess's mode-transition checks (0x536b30).
  float ComputeNavyOrderCategorySimilarityRatio(int excludeCurrent);
};

ASSERT_SIZE(TNavyMission, 0x3c);
