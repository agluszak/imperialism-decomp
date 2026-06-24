#pragma once

#include "game/TArmyMission.h"

// Mac: TDefendProvinceMission — army defend-province mission.
// VTABLE: IMPERIALISM 0x0065a680
class TDefendProvinceMission : public TArmyMission {
public:
  static float ComputeLocalSupportVectorScore(int nodeContext);
  static float ComputeCrossNationSupportVectorScore(int nodeContext);
};
