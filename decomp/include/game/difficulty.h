#pragma once

// Mac CodeWarrior names the game difficulty eDifficulty (TSimMgr::SetDifficultyLevel). The
// setup radio cluster and the game score read the five labels from string group 0x2737
// starting at entry 14.
enum eDifficulty {
  kDifficultyIntroductory = 0,
  kDifficultyEasy = 1,
  kDifficultyNormal = 2,
  kDifficultyHard = 3,
  kDifficultyNighOnImpossible = 4
};
