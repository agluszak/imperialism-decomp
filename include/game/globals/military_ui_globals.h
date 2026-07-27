#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/prelude.h"

extern int g_nIdleMeAnimationNextRegistryTag; // 0x00695934

// Battle-report marker blink state (TBattleReportView::DoIdle 0x4ad5a0): the tick counter
// fires the blink every 15th action-1 idle tick; the phase byte picks the marker sprite
// column to blit and is toggled after each blit.
extern unsigned char g_bBattleReportMarkerBlinkPhase; // 0x006a23b4
extern int g_nBattleReportMarkerBlinkTicks;           // 0x006a23b8

extern "C" {
// Per-unit-type strength-weighting percent (0x6953e8), read by TDefenseMinister::
// CreateEnemyPowerMap as weightPercent * TMilitaryUnit::strength34
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
