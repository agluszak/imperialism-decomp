#include "game/TGreatPower_internal.h"

#include "game/CIterator.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TSortedList.h"
#include "game/diplomacy_globals.h"

extern "C" {
extern short g_Classify_Nation_Military_LookupTable_00695CD4[][7];
}

int SumMilitaryUnitPowerWeights(TSortedList* unitList) {
  int powerSum = 0;
  CIterator unitIter(unitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    powerSum += g_Classify_Nation_Military_LookupTable_00695CD4[unit->unitTypeId04][0];
  }
  return powerSum;
}

float SumAlliedArmyScoreFactors(int targetNation) {
  float allySum = 0.0f;
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation) > 0) {
    do {
      int allyNation =
          g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allyIndex, targetNation);
      allySum = allySum + g_apNationStates[allyNation]->GetScoreFactorSlot23C();
      ++allyIndex;
    } while (allyIndex <
             g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation));
  }
  return allySum;
}

float SumAlliedNavyScoreFactors(int targetNation) {
  float allySum = 0.0f;
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation) > 0) {
    do {
      int allyNation =
          g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allyIndex, targetNation);
      allySum = allySum + g_apNationStates[allyNation]->GetScoreFactorSlot240();
      ++allyIndex;
    } while (allyIndex <
             g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(targetNation));
  }
  return allySum;
}

short* GetRelationStandingRowForNation(short nationSlot) {
  return &g_pDiplomacyTurnStateManager
              ->relationStandingScoreMatrix79c[nationSlot * kNationSlotCount];
}

int GetClampedQuarterYearTerm(void) {
  TSimMgr* localization = g_pLocalizationTable;
  int yearTerm = static_cast<short>(localization->quarterGateTick2c / 4);
  if (yearTerm >= 0x3c) {
    yearTerm = 0x3c;
  }
  return yearTerm;
}

float TruncatedScoreFactorToFloat(float score) {
  int truncated = static_cast<int>(score);
  if (truncated <= 1) {
    truncated = 1;
  }
  return static_cast<float>(truncated);
}
