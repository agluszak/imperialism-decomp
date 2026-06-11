#pragma once

// Mac: TDefendProvinceMission — army defend-province mission (hierarchy recovery in progress).
class TDefendProvinceMission {
public:
  static float ComputeLocalSupportVectorScore(int nodeContext);
  static float ComputeCrossNationSupportVectorScore(int nodeContext);
};
