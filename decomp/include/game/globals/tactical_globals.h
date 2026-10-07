#pragma once
#include "game/globals/global_types.h"

extern POINT g_ptTacticalAutoPlayModalMessage;

extern "C" {
extern int g_nUiFrameClipOriginX;
extern int g_nUiFrameClipOriginY;
extern CDib* g_pColorKeyCompositeDib;
extern short g_civilianTileOrderCursorTokenTable[];
extern int g_anUnitTypeTacticalRangeByType[30];
extern ArmyUnitCategoryStorage g_awTacticalUnitCategoryCodeBySlot[];
extern short g_awUnitCombatClassBySlot[32];
extern "C" char s_SourcePathUTacPlayer[];

extern double g_dTacticalCursorStrongRatioThreshold;

extern double g_dTacticalCursorOverwhelmRatioThreshold;

extern double g_dTacticalCursorWeakRatioThreshold;

extern double g_dTacticalCursorArtilleryParityThreshold;

extern double g_dTacticalCursorArtillerySuperiorityThreshold;

extern double g_dTacticalCursorAssaultRatioThreshold;

extern double g_dTacticalCursorRetreatRatioThreshold;

extern float g_afTacticalDirectFireFlagByCategoryCode[10];

extern short g_awTacticalUnitAiClassByUnitType[32];

extern short g_awTacticalUnitActionPointCostByType[32];

extern int g_anTacticalTileHeuristicWeightsByAiState[20][15];

extern short g_awTacticalCompositionReferenceProfiles[];

} // extern "C"

extern "C" {

extern int g_anWeightedNeighborUnitScoreByType[32];
extern short g_anUnitTypeCombatCategoryByType[32];
extern short g_awUnitTypeBaseActionPointTable[32];
extern short g_awTacticalFireSfxTokenByUnitType[32];
extern int g_anFortStrengthPointsByFortLevel[6];
extern short g_awTacticalMoveCostByCategoryAndTerrain[50];
extern float g_afTacticalNavyDamageScaleByUnitType[8];
extern float g_afTacticalNavyBaseAttackPowerByUnitType[8];
extern int g_anTacticalNavyUnitTypeByShipType[14];
extern float g_fTacticalRetreatQualityWeightDefault;
extern double g_dTacticalQualityFactorStep;
extern double g_dTacticalQualityFactorBase;
extern float g_fTacticalStrengthProjectionScale;
extern int (TArmyPlayer::* g_apfnTacticalTileHeuristicScorers[15])(class TTacticalUnit*, int);
extern float g_afTacticalDirectFireFlagByCategory[10];
extern float g_afTacticalBaseAttackPowerByUnitType[30];
extern float g_afTacticalMeleeMultiplierByCategory[8];
extern float g_afTacticalDamageScaleByUnitType[30];
extern float g_afTacticalAttackTerrainModifierByCategory[50];
extern float g_afTacticalDefenseTerrainModifierByCategory[50];
extern float g_afTacticalCoverDamageModifierByCategory[50];
extern char g_szBattleSetupTabPathFormat[];

} // extern "C"
