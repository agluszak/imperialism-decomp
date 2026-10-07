#pragma once
#include "game/globals/global_types.h"

extern "C" char* g_pShipFractionSharedText;

extern const int g_ShipOrderStatusStringIndexByResourceType[14];

// Horizontal source offsets for each naval resource type in the 0xdba roster atlas.
extern const short g_ShipRosterAtlasHorizontalOffsetByResourceType[14];

extern "C" {
extern "C" const char s_SourcePathUOceanViews[];

} // extern "C"

extern "C" {
extern char* g_pGamePreferencesSharedText;             // @ 0x65ddc8
extern const char* const g_pGamePreferencesAutoResKey; // @ 0x65ddcc
extern const int g_anGamePreferenceIndexByRow[5];      // @ 0x65dde0
}
