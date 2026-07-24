#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern POINT g_ptControlStringModalMessage;

extern short g_offerDeskSelectionIndexTable_00668568[8];

// Offer-desk CaptureLayoutF0 pairs (runtime-written).
extern "C" int g_aOfferDeskSheetLayoutInactive_006a5a00[2];
extern "C" int g_aOfferDeskSheetLayoutActive_006a5a28[2];
