#pragma once

#include "game/globals/global_types.h"

extern "C" {

// TMapMgr.cpp — river-flow sprite codes 0x0b..0x1a map through this 16-word table
// at 0x0065c648. The original indexed it as the live tail of a synthetic base at
// 0x0065c632, which overlaps TOcean::classTOcean and is not a standalone object.
extern const short g_anTerrainFlowTypeByRiverSpriteCode[16];

extern const short g_anTerrainFlowDirections[9][2];

} // extern "C"
