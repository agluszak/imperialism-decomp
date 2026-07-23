#pragma once

#include "decomp_types.h"

#include "game/tactical_ui/TTechMgr.h"
#include "game/nation/TMinor.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TZone.h"
#include "game/ui_core/TSortedList.h"

class TGreatPower;
class TSimMgr;

int SumMilitaryUnitPowerWeights(TSortedList* unitList);
float SumAlliedArmyScoreFactors(int targetNation);
float SumAlliedNavyScoreFactors(int targetNation);
short* GetRelationStandingRowForNation(short nationSlot);
int GetClampedQuarterYearTerm(void);
float TruncatedScoreFactorToFloat(float score);
void RecomputeNationOrderPriorityMetrics(void);
