#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern int g_nIdleMeAnimationNextRegistryTag; // 0x00695934

extern "C" {
// Per-unit-type strength-weighting percent (0x6953e8), read by TDefenseMinister::
// CreateEnemyPowerMap as weightPercent * TMilitaryUnit::field_34
// / 100.
extern short g_anUnitStrengthWeightPercentBySlot[32];

// Pointer to the current battle-report shared text (points at g_szEmptyString until
// something retargets it); both 0x4acb60 and 0x4af0b0 wrap it in a CString for
// SetControlHoverHelpText.
extern char* g_pBattleReportSharedText_0064dc30;

// Assert source-path string for the UDefenseMinister TU.
extern "C" const char s_SourcePathUDefenseMinister_00696860[];

extern const float g_DefenseMinisterWeightZero_006548E0;

} // extern "C"
