#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"


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
