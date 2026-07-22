#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern POINT g_ptTacticalAutoPlayModalMessage;        // @ 0x6a4650

extern "C" {
extern "C" const char s_SourcePathUTacPlayer_00699D84[];

extern double g_dTacticalCursorStrongRatioThreshold_00669508;

extern double g_dTacticalCursorOverwhelmRatioThreshold_00669510;

extern double g_dTacticalCursorWeakRatioThreshold_00669518;

extern double g_dTacticalCursorArtilleryParityThreshold_00669520;

extern double g_dTacticalCursorArtillerySuperiorityThreshold_00669528;

extern double g_dTacticalCursorAssaultRatioThreshold_00669530;

extern double g_dTacticalCursorRetreatRatioThreshold_00669538;

extern float g_afTacticalDirectFireFlagByCategoryCode_00669390[10];

extern short g_awTacticalUnitAiClassByUnitType_006693B8[32];

extern short g_awTacticalUnitActionPointCostByType_006693F8[32];

extern int g_anTacticalTileHeuristicWeightsByAiState_00699500[19][15];

extern short g_awTacticalCompositionReferenceProfiles_00697870[];

} // extern "C"
