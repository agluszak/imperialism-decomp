#pragma once

#include "decomp_types.h"

#include "game/tactical_ui/TTechMgr.h"
#include "game/nation/TMinor.h"
#include "game/navy/TShip.h"
#include "game/map/TZone.h"
#include "game/ui_core/TSortedList.h"

class TGreatPower;
class TSimMgr;

struct TurnOrderDispatchPacket {
  short turnTick;
  short orderKind;
  short payload;
  short flags;
};

void RecomputeNationOrderPriorityMetrics(void);
