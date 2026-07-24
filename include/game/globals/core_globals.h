#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern "C" int g_nStartupAutoResolutionMode;

// Private retail assert guards for TStream's McAppStream.cpp diagnostics.
extern int g_streamLine304AssertGuard;

extern int g_streamLine596AssertGuard;
