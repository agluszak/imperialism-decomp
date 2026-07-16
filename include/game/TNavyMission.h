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
  int navyField1c;                     // +0x1c
  TObject* navyField20;                // +0x20
  TMapOrderChildLinkNode* orderList24; // +0x24 -- head of child order-node chain
  int navyState28;            // +0x28 target-selection state (0 -> zone18 active, 1..2 -> zone14)
  float resourceWeights2c[4]; // +0x2c

  TNavyMission();
  TNavyMission(TZone* targetZone);

  virtual ~TNavyMission() override;                // slot 0x01 dtor 0x535590 / ??_G 0x535560
  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06
  virtual void
  Free() override; // slot 0x1c (TObject) 0x5364c0 -- releases orderList24 and deletes self

  virtual char ReturnFalseSlot28() override; // slot 0x28 0x535500
  virtual int ReturnZeroSlot2C(int* outBuffer, int unused)
      override; // slot 0x2c 0x536840 -- builds category weight vector, returns total
  virtual void RefreshSlot40() override; // slot 0x40 0x536b30 -- updates order-selection-mode state
  virtual void
  MissionSlot44() override; // slot 0x44 0x536e40 -- processes queued-order context mode
  virtual TMission* GetReplacementSlot48() override; // slot 0x48 0x536fc0
  virtual char ReturnFalseSlot54() override;         // slot 0x54 0x5354e0
  virtual int ReturnZeroSlot58() override;           // slot 0x58 0x535520
  virtual int ReturnZeroSlot5C() override;           // slot 0x5c 0x535540 -- returns this
  virtual float ReturnZeroFloatSlot68() override;    // slot 0x68 0x537f40
  virtual float
  ReturnZeroFloatSlot6C() override; // slot 0x6c 0x5378c0 -- dot product with baseline profile
  virtual float ReturnZeroFloatSlot74(
      void* candidate) override; // slot 0x74 0x537270 -- match delta vs candidate navy order
  virtual float ReturnZeroFloatSlot7C(
      void* candidate,
      void* targetProfile) override; // slot 0x7c 0x537610 -- order penalty vs target profile
  virtual void
  NoOpSlot84(int a,
             int b) override; // slot 0x84 0x536780 -- attach order child as queued and notify
  virtual void
  NoOpSlot8C(int a,
             int b) override; // slot 0x8c 0x5367d0 -- detach order child, clear primary if match
  virtual void NoOpSlot90(int a) override; // slot 0x90 0x536810 -- clear secondary order if match
  virtual char ReturnFalseSlot98()
      override; // slot 0x98 0x536740 -- clears queued order links/owner pointers, returns true

  // TNavyMission-introduced virtuals (TMission abstract slots 0x27+ / offset 0x9c+).
  // `pMapOrderEntry` is opaque here (RET 4 confirms one stack arg, real base body is a
  // pure no-op) -- overrides interpret it as the map-order entry the enclosing
  // MissionSlot44 dispatch passed (navyField20), concretely a TTaskForce* in every
  // known override (TControlSeaZoneMission/TBlockadePortMission/TBeachheadMission).
  virtual void NoOpSlot9C(void* pMapOrderEntry); // slot 0x27 0x5354c0
  // Returns the best neighbor port zone for the current nation (delegates to
  // targetZone14->SelectBestPrimaryNeighborForNationDiplomacyMask); every override
  // (TControlSeaZoneMission/TScatteredShipsMission) also returns a TZone*, and
  // TControlSeaZoneMission::GetReplacementSlot48 consumes the caller's result, so this
  // could not stay void (confirmed by 0x538900's disassembly storing EAX back into
  // targetZone18).
  virtual TZone* RefreshMissionPortZoneContextForNation(); // slot 0x28 0x536fa0
  virtual void
  ConsolidateMissionOrderEntriesByTargetAndQueue(int* pContextAnchor); // slot 0x29 0x5371d0
  virtual void
  QueueMissionOrdersByPriorityForContext(int pContextAnchor,
                                         int* ppSelectedChildNode); // slot 0x2a 0x537090
  // Selects the active target zone from lifecycle state28 (0 -> zone18, 1..2 -> zone14).
  virtual TZone* GetActiveTargetZoneByState28(); // slot 0x2b 0x537060

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
  // see g_NavyOrderDistanceDecayWeightTable_006978c8), then scores it against
  // resourceWeights2c via a Bhattacharyya-coefficient-style similarity:
  // sum(sqrt(resourceWeights2c[i] * vector[i])) / sum(resourceWeights2c[i]). Used to
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

private:
  // Shared by RefreshSlot40's mode-transition checks (0x536b30).
  float ComputeNavyOrderCategorySimilarityRatio(int excludeCurrent);
};

ASSERT_SIZE(TNavyMission, 0x3c);
