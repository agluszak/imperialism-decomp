#pragma once

// Mac: TNavyMission — navy mission scoring helpers (hierarchy recovery in progress).
class TNavyMission {
public:
  static float ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                           int nodeContext);
  static float ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                          int nodeContext);
};
