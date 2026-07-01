#pragma once

#include "game/TMission.h"

class TZone;
class TList;

// Navy-mission branch base (fills TMission abstract slots 0x27+; ctor 0x535470).
// VTABLE: IMPERIALISM 0x0065a818
class TNavyMission : public TMission {
  DECLARE_SERIAL(TNavyMission)
public:
  TZone* targetZone14;        // +0x14
  TZone* targetZone18;        // +0x18
  int navyField1c;            // +0x1c
  void* navyField20;          // +0x20
  TList* orderList24;         // +0x24
  float navyField28;          // +0x28
  float resourceWeights2c[4]; // +0x2c

  TNavyMission();
  TNavyMission(TZone* targetZone);
  virtual ~TNavyMission() override;

  virtual void WriteTo(TStream* stream) override;  // slot 0x05
  virtual void ReadFrom(TStream* stream) override; // slot 0x06

  virtual void CleanupTMissionAndReleaseOwnedOrders() override; // slot 0x27 / index 39 / offset 0x9c
  virtual uint EnsureMissionCurrentTargetContextIsValid() override; // slot 0x28 / index 40 / offset 0xa0
  virtual void ClearMissionQueuedOrderLinksAndOwnerPointers() override; // slot 0x29 / index 41 / offset 0xa4
  virtual void QueueMissionOrdersByPriorityForContext(int pContextAnchor, int* ppSelectedChildNode) override; // slot 0x2a / index 42 / offset 0xa8
  virtual int GetMissionOrderBudgetByMode(int mode) override; // slot 0x2b / index 43 / offset 0xac

  static float ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                           TZone* nodeContext);
  static float ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                          TZone* nodeContext);
};

ASSERT_SIZE(TNavyMission, 0x3c);
