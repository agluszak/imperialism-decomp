#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern POINT g_ptControlStringModalMessage;

extern short g_offerDeskSelectionIndexTable_00668568[8];

// Offer-desk Locate positions initialized by the retail startup table.
extern "C" CPoint g_offerDeskSheetPosition_006a5a00;
extern "C" CPoint g_offerDeskOffscreenPosition_006a5a28;
