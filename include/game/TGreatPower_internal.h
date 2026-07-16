#pragma once

#include "decomp_types.h"

#include "game/TTechMgr.h"
#include "game/TMinor.h"
#include "game/TShip.h"
#include "game/TZone.h"
#include "game/TSortedList.h"

class TGreatPower;
class TSimMgr;

int SumMilitaryUnitPowerWeights(TSortedList* unitList);
float SumAlliedArmyScoreFactors(int targetNation);
float SumAlliedNavyScoreFactors(int targetNation);
short* GetRelationStandingRowForNation(short nationSlot);
int GetClampedQuarterYearTerm(void);
float TruncatedScoreFactorToFloat(float score);
void RecomputeNationOrderPriorityMetrics(void);
