#pragma once

#include "decomp_types.h"

#include "game/tactical_ui/TTechMgr.h"
#include "game/nation/TMinor.h"
#include "game/navy/TShip.h"
#include "game/map/TZone.h"
#include "game/ui_core/TSortedList.h"

class TGreatPower;
class TSimMgr;

// 8-byte by-value record held in TGreatPower::turnSummaryQueue (recordSize14 == 8):
// written by AnnounceLater (0x4e2b00), consumed by the turn-message
// summary builder (0x4e2b70, TGreatPower_turn_summary.cpp).
struct TurnOrderDispatchPacket {
  short turnTick;
  short orderKind;
  short payload;
  short flags;
};

void RecomputeNationOrderPriorityMetrics(void);
