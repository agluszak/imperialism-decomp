#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern "C" char* g_pShipFractionSharedText_0065c830;

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// Per-type index into TShipView::Draw's 8-entry order-status
// string pool (GetString group 0x2760, one status line per naval order state);
// -1 = no status line for that resource type.
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
