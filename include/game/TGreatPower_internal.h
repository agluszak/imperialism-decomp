#pragma once

#include "decomp_types.h"

#include "game/tactical_ui/TTechMgr.h"
#include "game/nation/TMinor.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TZone.h"
#include "game/ui_core/TSortedList.h"

class TGreatPower;
class TSimMgr;

// 8-byte by-value record held in TGreatPower::turnSummaryQueue (recordSize14 == 8):
// written by DispatchTurnOrderActionSlotB0 (0x4e2b00), consumed by the turn-message
// summary builder (0x4e2b70, TGreatPower_turn_summary.cpp).
struct TurnOrderDispatchPacket {
  short turnTick;
  short orderKind;
  short payload;
  short flags;
};

int SumMilitaryUnitPowerWeights(TSortedList* unitList);
float SumAlliedArmyScoreFactors(int targetNation);
float SumAlliedNavyScoreFactors(int targetNation);
short* GetRelationStandingRowForNation(short nationSlot);
int GetClampedQuarterYearTerm(void);
float TruncatedScoreFactorToFloat(float score);
void RecomputeNationOrderPriorityMetrics(void);
