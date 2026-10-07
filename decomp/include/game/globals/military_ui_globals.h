#pragma once
#include "game/globals/global_types.h"

extern int g_nIdleMeAnimationNextRegistryTag;

extern bool g_bBattleReportMarkerBlinkPhase;
extern int g_nBattleReportMarkerBlinkTicks;
extern int g_InfoBarDummyOrigin[2];

extern "C" {
extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;
extern short g_anUnitStrengthWeightPercentBySlot[32];

extern char* g_pBattleReportSharedText;

// Assert source-path string for the UDefenseMinister TU.
extern "C" char s_SourcePathUDefenseMinister[];

extern const float g_DefenseMinisterWeightZero;

} // extern "C"
