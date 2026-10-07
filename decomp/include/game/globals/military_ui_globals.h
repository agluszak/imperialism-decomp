#pragma once
#include "game/globals/global_types.h"

extern int g_nIdleMeAnimationNextRegistryTag; // 0x00695934

extern bool g_bBattleReportMarkerBlinkPhase; // 0x006a23b4
extern int g_nBattleReportMarkerBlinkTicks;  // 0x006a23b8
extern int g_InfoBarDummyOrigin[2];

extern "C" {
extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;
extern short g_anUnitStrengthWeightPercentBySlot[32];

extern char* g_pBattleReportSharedText;

// Assert source-path string for the UDefenseMinister TU.
extern "C" const char s_SourcePathUDefenseMinister[];

extern const float g_DefenseMinisterWeightZero;

} // extern "C"
