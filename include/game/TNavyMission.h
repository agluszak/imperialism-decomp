#pragma once

#include "game/TMission.h"

// Navy-mission branch base (fills TMission abstract slots 0x27+; ctor 0x535470).
// VTABLE: IMPERIALISM 0x0065a818
class TNavyMission : public TMission {
public:
  int navyField14;
  int navyField18;
  int navyField1c;
  int navyField20;
  int navyField24;
  int navyField28;
  int navyField2c;
  int navyField30;
  int navyField34;
  int navyField38;

  static float ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                           int nodeContext);
  static float ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                          int nodeContext);
};

ASSERT_SIZE(TNavyMission, 0x3c);
