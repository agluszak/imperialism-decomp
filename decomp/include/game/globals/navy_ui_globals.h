#pragma once
#include "game/globals/global_types.h"

extern "C" char* g_pShipFractionSharedText_0065c830;

extern const int g_ShipOrderStatusStringIndexByResourceType_0065c7f8[14];

// Horizontal source offsets for each naval resource type in the 0xdba roster atlas.
extern const short g_ShipRosterAtlasHorizontalOffsetByResourceType_006985E8[14];

extern "C" {
extern "C" const char s_SourcePathUOceanViews_00698650[];

} // extern "C"

extern "C" {
extern char* g_pGamePreferencesSharedText_0065DDC8;             // @ 0x65ddc8
extern const char* const g_pGamePreferencesAutoResKey_0065DDCC; // @ 0x65ddcc
extern const int g_anGamePreferenceIndexByRow[5];               // @ 0x65dde0
}
