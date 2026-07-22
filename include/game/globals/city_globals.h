#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

// Initial city recruitment profiles for order slots 0x22..0x2a. 0x695c50.
extern short g_aInitialCityRecruitmentOrderProfiles[9][7];

extern "C" {
extern char g_Sanitize_City_Counter_Value_006A24D4;

} // extern "C"
