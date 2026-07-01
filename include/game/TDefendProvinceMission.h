#pragma once

#include "game/TArmyMission.h"

// Mac: TDefendProvinceMission — army defend-province mission.
// VTABLE: IMPERIALISM 0x0065a680
class TDefendProvinceMission : public TArmyMission {
  DECLARE_SERIAL(TDefendProvinceMission)
public:
  TDefendProvinceMission();
  virtual ~TDefendProvinceMission() override;

  virtual void Call30() override; // slot 0x0c / offset 0x30
  virtual void CleanupTArmyMissionAndReleaseChildContext() override; // slot 27 / 0x9c

  virtual void UpdateDefendProvinceMissionStateByNationTargetMatch(); // slot 48 / 0x30
  virtual void ComputeDefendProvinceMissionTerrainAdjacencyScoreFromTile14(); // slot 49 / 0x31
  virtual void PopulateDefendProvinceMissionResourceWeightsByDiplomacyContext(); // slot 50 / 0x32
  virtual bool HandleInvadeMissionActionType3ForTargetTile(int arg1, int arg2); // slot 51 / 0x33

  static float ComputeLocalSupportVectorScore(int nodeContext);
  static float ComputeCrossNationSupportVectorScore(int nodeContext);
};

ASSERT_SIZE(TDefendProvinceMission, 0x30);
