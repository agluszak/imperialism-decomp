#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern POINT g_ptTacticalAutoPlayModalMessage; // @ 0x6a4650

extern "C" {
extern int g_nUiFrameClipOriginX;
extern int g_nUiFrameClipOriginY;
extern CDib* g_pColorKeyCompositeDib;
extern short g_civilianTileOrderCursorTokenTable[];
extern int g_anUnitTypeTacticalRangeByType_006699E8[30];
extern ArmyUnitCategoryStorage g_awTacticalUnitCategoryCodeBySlot[];
extern short g_awUnitCombatClassBySlot[32];
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

extern int g_anTacticalTileHeuristicWeightsByAiState_00699500[20][15];

extern short g_awTacticalCompositionReferenceProfiles_00697870[];

} // extern "C"

extern "C" {

extern int g_anWeightedNeighborUnitScoreByType_006955F0[32];
extern short g_anUnitTypeCombatCategoryByType00669858[32];
extern short g_awUnitTypeBaseActionPointTable[32];
extern short g_awTacticalFireSfxTokenByUnitType[32];
extern int g_anFortStrengthPointsByFortLevel[6];
extern short g_awTacticalMoveCostByCategoryAndTerrain[50];
extern float g_afTacticalNavyDamageScaleByUnitType[8];
extern float g_afTacticalNavyBaseAttackPowerByUnitType[8];
extern int g_anTacticalNavyUnitTypeByShipType_00669D80[14];
extern float g_fTacticalRetreatQualityWeightDefault_00669EC0;
extern double g_dTacticalQualityFactorStep_00669EC8;
extern double g_dTacticalQualityFactorBase_00669ED0;
extern float g_fTacticalStrengthProjectionScale_00669F0C;
extern int (TArmyPlayer::* g_apfnTacticalTileHeuristicScorers_006994C0[15])(class TTacticalUnit*,
                                                                            int);
extern float g_afTacticalDirectFireFlagByCategory[10];
extern float g_afTacticalBaseAttackPowerByUnitType[30];
extern float g_afTacticalMeleeMultiplierByCategory[8];
extern float g_afTacticalDamageScaleByUnitType[30];
extern float g_afTacticalAttackTerrainModifierByCategory[50];
extern float g_afTacticalDefenseTerrainModifierByCategory[50];
extern float g_afTacticalCoverDamageModifierByCategory[50];
extern const char g_szBattleSetupTabPathFormat[];

} // extern "C"
