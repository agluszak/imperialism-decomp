#pragma once

#include "game/CString.h"

// reccmp `// GLOBAL:` address markers for symbols declared here live in
// src/game/global_data_tables.cpp only (one marker per address).

#include "decomp_types.h"

#include <new.h> // _PNH (CRT new-handler type)

#include "game/mfc.h"
#include "game/military_domain_types.h"
#include <afxtempl.h>
#include "game/app_init_globals.h"
#include "game/TCountry.h"
#include "game/TDisplayMgr.h"
#include "game/quickdraw_regions.h"
#include "game/strategic_terrain.h"
#include "game/TGreatPower.h"
#include "game/TMacViewMgr.h"
#include "game/TMinor.h"
#include "game/TView.h"
#include "game/TMouseCaptureState.h"
#include "game/TWNetSessionManager.h"
#include "game/timer_slots.h"

TGreatPower* GetNationStateBySlot(short slotId);
short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot);
TGreatPower* GetActiveNationState(void);
int GetTradeSummarySelectionTagByIndex(short index);

struct NationState;
struct TextStyle;
struct TQuickDrawSurfaceContext;
struct TCdAudioDevice;
class TArmyMgr;
class TAdmiral;
class TDiplomacyMgr;
class TNavyMgr;
class TShip;
class TSimMgr;
class TAssetMgr;
class TNewsMgr;

class TLanguageMgr;
class THelpMgr;
class TAnimator;

class TView;
class TViewMgr;
class TControl;
class TBackdropWindow;
class TOcean;
class TZone;
class TTaskForce;
class TMapMgr;
class TCivMgr;
class TTurnEventDialogFactoryRegistry;
class TSetupRandomMapPicture;
class TSoundPlayer;
class TInfoBarText;
class TTechMgr;
class TMultiplayerMgr;
class TNetMgr;
class TTradeMgr;
class TSoundResourceManager;
class TModuleLibraryCacheTableStateB;
class CDib;

struct GlobalViewportRectDefaultsRecord {
  int field0;
  RECT viewportBounds;
};

// Per-resource-type navy-order descriptor (base 0x00698108, stride 0x24). Ghidra's
// auto-analysis had split this into five separately-named "tables"
// (g_Resolve_Map_Order_LookupTable_00698108, g_Calculate_Mission_Order_LookupTable_0069810C,
// g_Task_Force_Order_LookupTable_00698110, g_Navy_Order_Priority_LookupTable_00698118,
// g_ResourceDescriptorWeightWord0Base0069811c); every one of those "tables" is read at
// per-index byte offset `index * 0x24` from a base address exactly 4/8/0x10/0x14 bytes
// apart -- confirmed via TShip.cpp/TTaskForce.cpp callsite disassembly, they are one
// struct array. The initializer and all indexed users agree on fourteen resource rows.
struct TNavyOrderResourceDescriptor {
  union {
    int resolveWeightDword;
    struct {
      short resolveWeight; // +0x00 (was g_Resolve_Map_Order_LookupTable_00698108)
      short resolveWeightHighWord;
    };
  };
  union {
    int calculateWeightDword;
    struct {
      short calculateWeight; // +0x04 (was g_Calculate_Mission_Order_LookupTable_0069810C)
      short calculateWeightHighWord;
    };
  };
  short taskForceWeight; // +0x08 (was g_Task_Force_Order_LookupTable_00698110's own +0x00)
  short pad0a;
  short stockCap; // +0x0c (was same table's +0x04); the navy-order normalization base
  short pad0e;
  int navyPriorityWeight; // +0x10 (was g_Navy_Order_Priority_LookupTable_00698118, read as a dword)
  short resourceDescriptorWeightWord0; // +0x14 (was g_ResourceDescriptorWeightWord0Base0069811c)
  short pad16;
  int enabledFlagOrBucketOffset; // +0x18 (was same table's +0x10; low short reused elsewhere
                                 // as a bucket offset, full dword tested for sign as an
                                 // enabled/disabled gate)
  short descriptorWeight;        // +0x1c (was DAT_00698124)
  short pad1e;
  // Per-order-type priority tier used by TNavyMgr::ResolveStrategicBattle's
  // candidate-tier scan/scoring loop (was DAT_00698128).
  short priorityTier; // +0x20
  short pad22;
};
ASSERT_SIZE(TNavyOrderResourceDescriptor, 0x24);

extern "C" TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[14];

// Per-category (0..3) capability metric baseline averages (0x006a3ec8): recomputed at
// runtime by RecomputeGlobalCapabilityAverages and read back as the normalization divisor
// by the navy/map-order per-category scoring helpers.
extern "C" int g_aCategoryMetricBaselineAverage[4];
// 0x54fd50: rebuilds g_aCategoryMetricBaselineAverage from the enabled resource types'
// descriptor blends (rounded average across enabled types 1..13).
void RecomputeGlobalCapabilityAverages(void);
extern "C" float g_fMissionScoreNormalizationDivisor;
extern "C" float g_fScatteredShipsMissionDefaultScore;

// Per-nation (0..6) output caches written by RecomputeNationOrderPriorityMetrics
// (0x53fe30): a queue-demand divergence score (blended from the 4-category
// TShip navy-order contribution percentages, normalized against
// g_Populate_Beachhead_Mission_LookupTable_00697958), a "mobile units"
// divergence/score pair (from militaryUnitList44 entries with a nonzero
// GetCategory, normalized against g_awTacticalCompositionReferenceProfiles_00697870),
// a "combined units" divergence (mobile + static units), and a final
// military-power-weighted order score.
extern "C" float g_afNationOrderQueueDivergence_006a3a88[7];
extern "C" short g_nArmsBasicResourceOfferSplitCount_006a3a54;
extern "C" short g_nArmsAdvancedResourceOfferSplitCount_006a3a58;
extern "C" float g_afNationOrderQueueDivergenceMirror_006a3ac0[7];
extern "C" float g_afNationMobileUnitDivergence_006a3ae0[7];
extern "C" float g_afNationWeightedMilitaryOrderScore_006a3b20[7];
extern "C" float g_afNationCombinedUnitDivergence_006a3b50[7];
extern "C" float g_afNationMobileUnitScore_006a3b88[7];

// Class-id -> capability-slot lookup table (0x698120, 14 entries, only the leading
// classId field is read by GetEnabledIndustryCapabilitySlotByClass; the remaining 8
// ints of each 0x24-byte record are unmapped (raw, preserved for byte-exact datacmp)).
// Index 0 (classId -1) is never actually reached by that scan (see the function body).
struct IndustryCapabilityClassSlotEntry {
  int classId;
  int raw[8];
};
extern "C" IndustryCapabilityClassSlotEntry g_aIndustryCapabilityClassSlotTable[14];

// Six admiral-skill rows. Columns 0..2 select an estimated ship count and columns
// 3..5 select class accuracy; each triplet is a percentage distribution.
extern "C" short g_aNavalIntelligenceAccuracyProfiles[6][6];
extern "C" unsigned char g_bPerfectNavalIntelligenceCheat;

short GetResourceTypeRandomDrawBlockFlag(short resourceType);
short GetResourceDescriptorWord0CByType(short resourceType);
short GetResourceDescriptorWord10ByType(short resourceType);
short GetResourceDescriptorWord14ByType(short resourceType);
short GetResourceDescriptorWord18ByType(short resourceType);
short GetResourceDescriptorWeightWord1ByType(short resourceType);
short GetResourceDescriptorWord20ByType(short resourceType);
short GetResourceDescriptorWord08ByTypeOffset(short resourceType, short subslot);

// Formats "<count><sep><commodity name>" into `out` (defined in TNavyMgr.cpp; see
// there for the full field note). commodityCode selects the localized name;
// count < 0 suppresses the numeric prefix entirely.
void FormatLocalizedCommodityCountLabelByIndex(CString* out, unsigned int commodityCode,
                                               short count);

// Per-unit-type military stat records (7 shorts per type, record base 0x695cd2):
// column 0 = category flag (0x10 = counted toward power/cost), column 1 = power/cost
// points. See TMilitaryUnit::GetArmsCarried (0x5c3400).

// Per-unit-type stat table (7 shorts per type; unit types 0x00-0x1d) and per-stat
// divisor baseline used by TMilitaryUnit::GetAttribute (0x5c3530).
extern "C" short g_UnitTypeStatTable_0066EB88[30][7];
extern "C" short g_UnitTypeStatDivisorTable_0066ED30[7];

// TMilitaryUnit exposes the listing-backed instance and static accessors over
// these tables; their declarations live on the owning class.
// 0x54fee0: g_aCategoryMetricBaselineAverage[index] (returns the int metric, not a pointer
// despite Ghidra's placeholder name).
int GetNavyContextPointerFromGlobalTableByIndex(int index);

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. The foreign-minister tables have eight entries;
// the defense-minister tables have six. Used by TGreatPower vtable slots 0x88-0x8c.
extern "C" {
extern float g_DAT_Value_00653308[8];
extern float g_DAT_Value_00653328[6];
extern float g_DAT_Value_00653340[8];
extern float g_DAT_Value_00653360[6];
extern float g_DAT_Value_00653378[8];
extern float g_DAT_Value_00653398[6];
extern float g_DAT_006533b0_Value_006533B0[8];
extern float g_DAT_006533d0_Value_006533D0[6];
extern float g_DAT_006533e8_Value_006533E8[8];
extern float g_DAT_Value_00653408[6];

// Float constants used by the TGreatPower relative-power-score family
// (vtable slots 0x8e-0x9e, bodies 0x004e07b0..0x004e1c20).
extern const float g_Compute_Advisory_Handler_LookupTable_00653700; // 0.0f
extern float g_Compute_Advisory_Handler_LookupTable_00653714;       // -0.25f
extern float g_Iterate_Linked_List_Value_00653718;                  // 0.25f
extern float g_Compute_City_Order_Value_0065371C;                   // 0.5f
extern float g_Compute_Advisory_Handler_LookupTable_00653720;       // -90.0f
extern float g_Compute_Advisory_Peer_LookupTable_00653724;          // -0.5f
extern float g_afAdvisoryMissionTierThresholdByMinisterSkill_00653F18[5][6];
extern const float g_Compute_Advisory_Zero_00653FD0;
extern float g_Compute_Advisory_Map_Value_00653FD4;
extern double g_Compute_Advisory_MinusSix_00653FE8;
extern double g_Compute_Advisory_MinusHundred_00653FF0;
extern float g_Compute_Advisory_MinusSixFloat_00653FF8;
extern double g_Compute_Advisory_Hundred_00654000;
extern double g_Compute_Advisory_OnePointFive_00654008;

// 0x653704-0x653710 — production-tier classification constants (TGreatPower slot
// 0x82, body 0x004e2880): -1.0, 2.0, 1.0, -2.0.
extern float g_Classify_Nation_Military_Value_00653704;
extern float g_Classify_Nation_Military_Value_00653708;
extern float g_Classify_Nation_Military_Value_0065370C;
extern float g_Classify_Nation_Military_Value_00653710;

// Per-order-type sort priority table (slot 0x55 selection sort).
extern short g_DAT_006966d0_Value_006966D0[12];
// Cursor resource id by civilian-tile-order action code (12 entries).
extern short g_civilianTileOrderCursorTokenTable[];
// Cursor resource ids keyed by the military/civilian map state classifiers (12 entries each).
extern short g_mapCursorTokenByStateIndex_00695668[12];
extern short g_civilianMapCursorTokenByStateIndex_00695680[12];
// Per-unit-type tactical category code (slot 0x11 garrison sweep).
extern int g_anUnitTypeTacticalRangeByType_006699E8[30];
extern ArmyUnitCategoryStorage g_awTacticalUnitCategoryCodeBySlot[];
extern int g_nTacticalTileWidthPx_006A5430;
extern int g_nTacticalTileRowHeightPx_006A5434;
extern int g_nTacticalBattlefieldSurfaceWidth_006A5448;
extern int g_nTacticalBattlefieldSurfaceHeight_006A544C;
extern int g_nTacticalUnitSpriteCellWidth_006A5498;
extern int g_nTacticalUnitSpriteCellHeight_006A549C;

// Per-unit-type combat/composition class (0x695380), read by
// FormStacks when building a TArmyStack's
// field4/field6 composition code.
extern short g_awUnitCombatClassBySlot[32];
// Stack composition class lookup (0x6953c0), indexed [minClass + maxClass*4]; true
// bound unconfirmed beyond the observed min/max class range (1..5-ish).
extern unsigned char g_abStackCompositionClassTable[16];
// Per-unit-type strength-weighting percent (0x6953e8), read by TDefenseMinister::
// BuildHexAreaTileIndexListIntoAllocatedBuffer as weightPercent * TMilitaryUnit::field_34
// / 100.
extern short g_anUnitStrengthWeightPercentBySlot[32];

// Per-civilian-order-type map-improvement sprite class (0x697040), read by
// TMapMgr::GetMapImprovementSpriteBaseOffset via TCivUnit::orderType; only indices 0-8 are
// non-zero (values 0-8), true bound beyond that unconfirmed.
extern short g_anMapImprovementSpriteClassByOrderType[9];

// Per-fort-level attacker penalty percent (0x695568), indexed by
// Province::fortLevel03; observed values 100/85/75/65/0/0/0/0 for levels
// 0-7 (only the low byte of each int is ever read). Used by
// TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState to gate the per-unit meter snapshot.
extern int g_anFortLevelAttackerPenaltyPercentByLevel[8];
// Per-unit-type blink/boost eligibility flag (0x64c808), indexed by TUnit::orderType; true
// bound unconfirmed beyond the observed ~28 nonzero/zero entries.
extern unsigned char g_abUnitTypeBlinkEligibilityFlag[32];

// Four per-unit-type meter-scoring tables read by
// TArmyStack::AccumulateWeightedMeterAndCountFromEligibleLinkedEntries, all indexed by
// TUnit::orderType; true bounds unconfirmed beyond the observed sampled entries.
extern int g_anWeightClassByOrderType[32];         // 0x64c790
extern short g_anScaledFactorByOrderType[32];      // 0x64c660
extern float g_afPercentEfficiencyByOrderType[32]; // 0x64c6a0
extern int g_anCountWeightByOrderType[32];         // 0x695578

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's city stock block by TGreatPower slot 0x39 (0x004df810).
extern short g_Rebuild_Primary_Nation_Value_00653570[5][0x17];
} // extern "C"

// ============================================================================
// Diplomacy globals
// ============================================================================

extern "C" {
class TApplication;
class TAmbitApplication;
class TTacticalBattle;
class ImperialismApp;

extern int g_nOverlayClipCacheParamX;
extern int g_nOverlayClipCacheParamY;
extern int g_Reset_Quick_Draw_Value_0064B8F0;
extern int g_Reset_Quick_Draw_Value_0064B8F4;
extern const short g_Reset_Quick_Draw_WordState_0064B8F8;
extern short g_Reset_Quick_Draw_State_006A1D10;
extern int g_nQuickDrawPenHorizontalSize;
extern int g_nQuickDrawPenVerticalSize;
extern int g_bQuickDrawStrokePairDirty;
// The cached QuickDraw clip region — a heap CRgn built by the CRT static-init ctor
// at 0x494040 (ported in quickdraw_rendering.cpp as TQuickDrawClipStateInitializer).
// GetClip seeds from it; SetClip (0x495a30) copies a RgnHandle's region into it.
extern CRgn* g_pGlobalClipRegionHandleObject;
extern COLORREF g_QuickDrawForegroundColor;
extern CFont* g_pQuickDrawCachedUiFont;
extern TextStyle g_QuickDrawCachedFontPreset;
extern unsigned char g_bQuickDrawCachedFontDirty;
extern char g_szQuickDrawFontFaceSystem[];
extern char g_szQuickDrawFontFaceBookAntiqua[];
extern char g_szQuickDrawFontFaceSmallFonts[];
extern const char* const g_apszQuickDrawFontFaceNames[5];
// Measure-text cached font cluster (0x6a1d48-0x6a1d56): same shape as the draw-font
// cluster above. The preset's styleRef6 field IS the current text color (written by
// SetQuickDrawFillColor, read as COLORREF by the paint paths; the original PDB labels
// those 4 bytes g_uQuickDrawCurrentColor — it's the same field, not a separate global).
extern CFont* g_pQuickDrawCachedMeasureFont;       // 0x6a1d48
extern TextStyle g_QuickDrawMeasureFontPreset;     // 0x6a1d4c
extern unsigned char g_bQuickDrawMeasureFontDirty; // 0x6a1d56
extern COLORREF g_QuickDrawBackgroundColor;
extern int g_nQuickDrawOriginX;
extern int g_nQuickDrawOriginY;
extern int g_nQuickDrawResolvedTextOriginX;
extern int g_nQuickDrawResolvedTextOriginY;
// TODO(hedge): only observed as the left/top of a view-frame clip bounds rect in
// TTacticalBattleView::DrawUiTilesAndOverlay; sole writer (0x005ad9e2) not yet
// identified/named. 0x6a5458/0x6a545c
extern int g_nUiFrameClipOriginX;
extern int g_nUiFrameClipOriginY;
extern TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext;
extern TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext;
extern TQuickDrawSurfaceContext* g_pCitySiteCachedPrimaryRenderSurfaceContext;
extern CDib* g_pColorKeyCompositeDib;
// TCitySiteView's currently painted six-neighbor highlight set. Each entry is a map tile
// index or -1; the paint pass restores the previous cells before replacing this cache.
extern short g_aStrategicMapNeighborHighlightTiles_00697320[6];
// Strategic-map preview cursor and the two half-cell parity remainders maintained while
// converting its point into a viewport cell.
extern CPoint g_MapInteractionPreviewPoint_006a3370;
extern int g_MapInteractionPreviewRowParity_006a33b4;
extern int g_MapInteractionPreviewColumnParity_006a33b8;
// Owner-nation tag (0..23) to the QuickDraw palette index used behind ocean-map
// order previews and garrison badges.
extern const unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24];
// Per-owner outline palette used by the ocean overview's direct 16x16 neighbor-edge pass.
extern const unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24];
// Secret garrison-close names used by the retail easter-egg path.
extern const char g_szGarrisonSecretNationNameFrog[];
extern const char g_szGarrisonSecretUnitNameSnidely[];
extern const unsigned char g_bDrawOceanRouteOverlay;
extern const unsigned char g_bTransferOceanViewportToActiveSurface;
extern const unsigned char g_bDrawOceanZoneLabels;
extern const unsigned char g_bDrawOceanNationLabels;
extern CDC* g_pQuickDrawMemoryDc;
extern HGDIOBJ g_hQuickDrawSavedBitmap;
extern int g_nActiveQuickDrawSurfaceFlags;
extern int g_QuickDrawSetCursorAssertGate;
extern int g_QuickDrawGetCursorAssertGate;
extern const int g_pTradeSummarySelectionMap[23];
extern const int kTradeSellPropagationTags[17];
extern const int g_tradeBidNationMetricControlTags[24];
extern const unsigned int g_majorTreatyPanelTags[7];
extern const unsigned int g_minorTreatyPanelTags[16];
extern const unsigned int g_majorTreatyCellTags[7];

// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern TMinor* g_apSecondaryNationStateSlots[36];
// Parallel to g_apMinorNationCapabilityObjects[16] — aux runtime terrain rows.
extern TMinor* g_apNationAuxRuntimeStateSlots[16];
extern TMinor* g_apMinorNationCapabilityObjects[16];
extern TGreatPower* g_apNationStates[7];
extern TGreatPower* g_apNationStates_End;
extern TSimMgr* g_pSimMgr;
extern THelpMgr* g_pHelpMgr;
extern TNewsMgr* g_pNewsMgr;
extern TAmbitApplication* g_pGlobalUiRootController;

// The live tactical battle (turn-event 0x29/0x2a receive dispatch target).
extern TTacticalBattle* g_pActiveTacticalBattle;
// OR-accumulator for the turn-event-0x2b presence-mask exchange.
extern int g_nTurnEvent2BNationMaskAccumulator;
extern int g_anWeightedNeighborUnitScoreByType_006955F0[32];
extern short g_anUnitTypeCombatCategoryByType00669858[32];
extern short g_awUnitTypeBaseActionPointTable[32];
extern short g_awTacticalFireSfxTokenByUnitType[32];
extern "C" const char s_SourcePathUTacPlayer_00699D84[];
extern const char* g_pszEmptyTextRef_00669db8;
extern int g_anFortStrengthPointsByFortLevel[6];
extern short g_awTacticalMoveCostByCategoryAndTerrain[50];
extern double g_dTacticalCursorStrongRatioThreshold_00669508;
extern double g_dTacticalCursorOverwhelmRatioThreshold_00669510;
extern double g_dTacticalCursorWeakRatioThreshold_00669518;
extern double g_dTacticalCursorArtilleryParityThreshold_00669520;
extern double g_dTacticalCursorArtillerySuperiorityThreshold_00669528;
extern double g_dTacticalCursorAssaultRatioThreshold_00669530;
extern double g_dTacticalCursorRetreatRatioThreshold_00669538;
extern float g_afTacticalNavyDamageScaleByUnitType[8];
extern float g_afTacticalNavyBaseAttackPowerByUnitType[8];
extern int g_anTacticalNavyUnitTypeByShipType_00669D80[14];
extern float g_fTacticalRetreatQualityWeightDefault_00669EC0;
extern double g_dTacticalQualityFactorStep_00669EC8;
extern double g_dTacticalQualityFactorBase_00669ED0;
extern float g_fTacticalStrengthProjectionScale_00669F0C;
extern float g_afTacticalDirectFireFlagByCategoryCode_00669390[10];
// Requires the TacticalTileHeuristicScorerFn typedef from game/TArmyPlayer.h at the
// point of use; declared here per the one-home-for-globals rule.
class TArmyPlayer;
extern int (TArmyPlayer::* g_apfnTacticalTileHeuristicScorers_006994C0[15])(class TTacticalUnit*,
                                                                            int);
extern short g_awTacticalUnitAiClassByUnitType_006693B8[32];
extern short g_awTacticalUnitActionPointCostByType_006693F8[32];
extern int g_anTacticalTileHeuristicWeightsByAiState_00699500[19][15];
extern float g_afTacticalDirectFireFlagByCategory[10];
extern float g_afTacticalBaseAttackPowerByUnitType[30];
extern float g_afTacticalMeleeMultiplierByCategory[8];
extern float g_afTacticalDamageScaleByUnitType[30];
extern float g_afTacticalAttackTerrainModifierByCategory[50];
extern float g_afTacticalDefenseTerrainModifierByCategory[50];
extern float g_afTacticalCoverDamageModifierByCategory[50];
extern "C" const char g_szBattleSetupTabPathFormat[];
extern "C" const char s_szDoubleNewline_00699438[];
extern char g_nForceTacticalBattleViewFlag_006A4758;
// The multiplayer/game-flow singleton (0x6a43c8); every turn-event emitter is a
// __thiscall method on it (original callsites load ECX from here).
extern TMultiplayerMgr* g_pGameFlowState;
// WNetMgr.cpp TU globals (0x6a5fxx band), consumed by TNetMgr::Send / TWNetSessionManager.
// The pending-packet queue and its two serialization siblings are file-scope MFC template
// statics (see the typed C++ section below); the previous six raw queue globals were the
// members of the CList at 0x6a5f40.
extern int DAT_006a601c;
extern int g_suppressUnexpectedDirectPlaySystemMessageAssert006a6020;
// City-order capability rule-table pointer slots written into TTechMgr+0x264 as tech
// unlocks are applied (default at construction, alternates for tech ids 0x0b/0x16).
// 26 (start, end) capability-priority range pairs (see the .cpp note).
extern short g_anCapabilityPriorityRangePairs[53];
extern const char s_DataDirectoryPath_006942A8[];
extern const char s_IrgGlobPattern_006942FC[];
extern const char s_NoLanguageFilesMessage_006942B4[];
extern const char s_OutOfMemoryText_006941F0[];
extern const char s_ErrorCaption_00694204[];
extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;
extern TNavyMgr* g_pNavyOrderManager;
extern "C" TShip* g_pNavyPrimaryOrderListHead;
extern "C" TAdmiral* g_pNavySecondaryOrderListHead;
extern TArmyMgr* g_pMapContextActionManager;
// Two 0x20-byte flag tables installed into TArmyMgr+0x14/+0x18 by
// InitializeMapContextActionManager (0x4a18f0); 8 rows x 4 flag bytes.
extern const unsigned char g_MapContextStaticTable_00695448[0x20];
extern const unsigned char g_MapContextStaticTable_00695428[0x20];
// Pointer to the current battle-report shared text (points at g_szEmptyString until
// something retargets it); both 0x4acb60 and 0x4af0b0 wrap it in a CString for
// SetControlHoverHelpText.
extern char* g_pBattleReportSharedText_0064dc30;
extern char* g_pMiniCivSharedText_0064cb18;
extern char* g_pShipFractionSharedText_0065c830;
extern char* g_pDiplomacyPanelEmptyText_00654ec8;
extern char* g_pStatusPictureMainSharedText_00668b88;
extern char* g_pLoungeLocalPlayerNameSharedText_0065c160;
extern int g_lastEdgeAutoScrollTick16;
extern int g_nSaveFormatVersion;
extern const int g_nAmbitSaveFileMagic;
extern const int g_nCurrentAmbitSaveFormatVersion;
extern const char g_szUAmbitSourcePath[];
extern const short g_aDiplomacyPlanningQuarterPhaseByNation[7];
extern const unsigned int g_anScenarioScriptInstructionTags[27];
extern void (TSimMgr::* g_apfnScenarioScriptInstructionHandlers[27])(void*);
extern unsigned char g_bScenarioScriptTerminationRequested;
extern int g_nScenarioScriptInstructionCount;
// Gates the assert-messagebox in TTaskForce::CarryOutOrders' default
// (unhandled ship-order kind) case; not yet recovered beyond that one read site.
extern int g_UnknownMapOrderExecutionGuard_006a3ee0;
// Guards the nil-pointer assert in TColorFill::Draw (0x004ff1c0, TColorFill.cpp);
// no write site found anywhere in ported source, so this may be a debug/never-reached
// assertion path in the retail build rather than a genuine run-once flag.
extern int g_colorFillAssertGuard_006a30b4;
extern char g_szLiteralL_00694250[];
extern char g_szCmdSwitchLangQuit_00694254[];
extern ImperialismApp* g_pImperialismApp;
extern int DAT_006a1350;
extern _PNH g_pfnPreviousNewHandler;
// Read only by ImperialismApp's developer assert command; no writer exists in the retail
// image, so the command deliberately exercises the nil-pointer assert path.
extern void* g_pAmbitDeveloperAssertProbe_006A1358;
extern short g_industryActionCostWeightResCode09[16];
extern short g_industryActionCostWeightResCode08[16];
extern short g_industryActionCostWeightResCode10[16];
extern short g_industryActionCostWeightResCode0B[16];
extern short g_industryActionCostWeightResCode03[16];
extern short g_industryActionCostWeightResCode0C[16];
struct AiCityActionCostProfile {
  short primaryMetricCode;
  short primaryMetricMultiplier;
  short secondaryMetricCode;
  short secondaryMetricMultiplier;
  short baseCost;
  short contextBiasSelector;
  short actionId;
};
ASSERT_SIZE(AiCityActionCostProfile, 14);
extern AiCityActionCostProfile g_aiCityActionCostProfiles[30];
extern float g_AiDevelopmentResourceBudgetScale_00650758;
extern short g_cachedAiCityActionNationSlot_006967d4;
extern short g_cachedAiCityActionTurnTick_006967d8;
extern float g_cachedAiCityActionContextBias[3];
// 17 (x,y) anchor points used to build the 16 city-building hover/hit-test rects (each a
// fixed 10x10 box at its anchor, except slots 10-11 which span between two consecutive
// anchors), plus a trailing (1,0) pair with no known consumer that shares this data blob.
// 0x696198.
extern short g_anCityBuildingSlotCoords[36];
// Per-building-slot hover/hit-test rects (indexed by slotId, see
// TToolBarCluster::HandleCityBuildingHoverSelection), built by
// InitializeCityBuildingHoverSelectionRects_004b95c0. 0x6a2998.
extern CRect g_aCityBuildingHoverSelectionRects[16];
// Packed int table consumed by the city-building screen layout (icon/highlight coordinates
// and 0/1 flags; per-field semantics not yet recovered). Populated by
// InitializeCityBuildingLayoutData. 0x6a24e8.
extern int g_anCityBuildingLayoutValues[164];
// 31 action-button rects for the city-building screen, placement-constructed by
// InitializeCityBuildingLayoutData (immediately after g_anCityBuildingLayoutValues). 0x6a2778.
extern CRect g_aCityBuildingActionRects[31];
// QuickDraw OpenRgn/CloseRgn recording accumulator (QDFrameRect XORs framed rects into it).
extern HRGN g_hOpenRgnAccumulator;
extern char g_Sanitize_City_Counter_Value_006A24D4;
extern double DAT_0066fad0;
extern char* g_pNationInfoEmptyText_0066f050;
extern short g_anAbilityStatusPictureIndex_0066F058[29];
extern char g_szListSeparator_00695760[];
extern char g_szPlusPrefix_00698494[];
extern char g_szListConjunction_00698498[];
extern short g_overlaySfxSeasonWord_0066f0a6;
extern TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;
// Cached CCommandLineInfo::m_bShowSplash (cmdInfo+0x04), not m_nShellCommand.
extern BOOL g_cachedShowSplashFlag;
extern TBackdropWindow* DAT_006a2050;
extern void* DAT_006a2054;
extern LPCSTR g_apFontFiles[];
extern int g_nDibOrientationFlag_006A1890;
extern int g_nAuxOutputDeviceIndex;
extern void* g_pScopedMapQuickDrawViewContext;
extern CDC* g_pScopedMapQuickDrawDcHandleObject;
// One-slot CTemporaryRegion reuse cache (see CTemporaryRegion.h).
extern RgnHandle g_pTemporaryRegionCache;
extern int g_nRandomMapSelectedNationSlot00698AB0;
extern char g_szCountryNameProfileKey00698AE0[];
}

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// Per-type index into TShipView::Draw's 8-entry order-status
// string pool (GetString group 0x2760, one status line per naval order state);
// -1 = no status line for that resource type.
extern const int g_ShipOrderStatusStringIndexByResourceType_0065c7f8[14];
// Horizontal source offsets for each naval resource type in the 0xdba roster atlas.
extern const short g_ShipRosterAtlasHorizontalOffsetByResourceType_006985E8[14];
extern TInfoBarText* g_pCursorControlPanel;
extern POINT g_ptControlStringModalMessage;
extern TTradeMgr* g_pNationInteractionStateManager;
extern CString g_cstrCountryNameSettingValue006A4220;
extern TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture006A4268;
extern "C" short g_aTradeDealCategoryOrder_0066D810[0x11];
extern "C" const double g_TradePowerIdentity_0066D8E0;
extern "C" const short g_aTradeItemBasePriceByCategory_0069A910[0x11];
extern "C" const unsigned int g_tradeCommodityRowTagTable[17];
// Shared substitution value read by TTradeTotalsView::Draw (0x5c1bd0) as
// the sole scanBracketExpressions() argument for its "balance" row template (GetString
// group 0x2740 idx 0x1b). The original's raw bytes are a compile-time-constant pointer
// to an empty string (not a deferred-construction CString), so this is modeled as a
// plain pointer aliasing the shared g_szEmptyString buffer, matching the
// g_pszEmptyTextRef_00669db8 idiom. Not yet pinned to a writer if one exists.
extern const char* g_cstrTradeTotalsBalanceSubstitution0066DB50;
extern GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord;
extern GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord;
extern TWNetSessionManager g_NetworkSessionManager006a5f60;
extern const GUID g_ImperialismDirectPlayApplicationGuid0066f968;
extern CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_RuntimeSelectionRecords006a15e0;
// Global TNetMgr (0x6a6014), created by TMultiplayerMgr session init.
extern TNetMgr* g_pNetMgr006a6014;
// WNetMgr.cpp file-scope MFC template statics (all atexit-destroyed; static-init
// helpers 0x5e26d0/0x5e2720/0x5e2770). Vtables 0x66fa50 (CList) / 0x66fa68 (CArray)
// are this TU's twin copies of the template vtables (recover-class once merged them
// into TNetMgr's vtable annotation by adjacency). Element/name identification is
// behavioral: Serialize instantiations at 0x5e4610/0x5e4830, node size 0xc,
// ctor blockSize 10.
// UGameWindow/dialog-factory widget build stack (IncludeView TU band). The out-of-line
// "PushUiResourcePoolNode"/"PopUiResourcePoolNode" bodies at 0x479b00/0x479a80 are this
// list's CList<TView*,TView*>::AddTail/RemoveTail twin copies; the "current panel" global
// the factory bodies read at 0x6a13e8 is this object's m_pNodeTail (i.e. GetTail()).
extern CList<TView*, TView*> g_UiWidgetBuildStack006a13e0;
extern CArray<void*, void*> g_WNetSerializedPtrArrayA006a5f10;
extern CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_WNetSerializedPtrArrayB006a5f28;
extern CList<void*, void*> g_WNetPendingPacketList006a5f40;
extern POINT g_ptNetworkModalMessage006a5ed8;
extern TTechMgr* g_pCityOrderCapabilityState;
extern TSoundResourceManager g_soundResourceManager;
// CD-audio MCI device singleton (see game/cd_audio.h).
extern TCdAudioDevice g_cdAudioDevice; // 0x006a60bc
// Audio timer-slot registry (see game/timer_slots.h): 10 callbacks + 10 live timer ids.
extern TimerSlotCallback g_timerSlotCallbacks[10]; // 0x006a5cf8
extern UINT g_timerSlotIds[10];                    // 0x006a5c98
extern int g_timerDispatchSuppressAssert;          // 0x006a5d24
// Counts idle/audio-state polls before another random cue selection attempt.
extern short g_randomAudioCuePollCounter; // 0x006a4520
extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];
// Tactical unit facing-offset table (0x006a4780); see global_data_tables.cpp.
extern POINT g_aTacticalUnitFacingOffsetTable[29][7][2];
extern TDisplayMgr* g_pDisplayMgr;
extern int g_nUiAnimatorSurfaceBoundsWidth;   // 0x006a2228
extern int g_nUiAnimatorSurfaceBoundsHeight;  // 0x006a222c
extern int g_nIdleMeAnimationNextRegistryTag; // 0x00695934
extern TMacViewMgr* g_pStrategicMapViewSystem;
extern TViewMgr* g_pUiRuntimeContext;
extern "C" int g_diplomacyActionButtonTagTable_00696960[6];
extern "C" unsigned int g_councilControlTagTable[6];
extern "C" short g_aDiplomacyRelationPaletteColorCodes[7];
extern "C" short g_infoPanelLabelXByRow_006969b0[4];
extern "C" short g_infoPanelLabelYByRow_006969c0[4];
extern "C" COLORREF g_defaultDropShadowTextColor;
extern TAssetMgr* g_pUiViewManager;
extern TLanguageMgr* g_pLanguageMgr;
extern TAnimator* g_pUiAnimator;

// ============================================================================
// McAppUI globals
// ============================================================================

extern "C" {

// Gate checked before touching a control's native window (e.g. ValidateRect /
// InvalidateRect): non-zero once the UI subsystem/screen is realized.
extern int g_McAppUiActiveFlag_006950AC;

// Gate checked in the QuickDraw/GDI draw path before temporarily clearing the UI
// invalidation flag.
extern int g_McAppUiDrawGate_006A1AF8;

// Gate checked before the invalidation-flag assert/log call in the child-detach path.
extern int g_McAppUiFlag_006A1AE0;

// Gate checked before the UI resource-entry allocation assert in TEventHandler slot 0x08.
extern int g_McAppUiFlag_006A1AE4;

// Further invalidation-flag assert gates (McAppUI.cpp lines 1914 / 1922).
extern int g_McAppUiFlag_006A1AFC;
extern int g_McAppUiFlag_006A1B00;

// Per-line one-shot invalidation-flag assert gates used by TWindow's UI slot bodies.
extern int g_McAppUiFlag_006A1B04;
extern int g_McAppUiFlag_006A1B08;
extern int g_McAppUiFlag_006A1B10;
extern int g_McAppUiFlag_006A1B14;
extern int g_McAppUiFlag_006A1B18;
extern int g_McAppUiFlag_006A1B1C;
extern int g_McAppUiFlag_006A1B0C;

// Reentrancy guard for the root UpdateWindow pass driven by TView slot 0x4f.
extern int g_McAppUiUpdateWindowRecursionGuard_006A1AF0;

// Active QuickDraw origin/render context view for slot 0x3e.
extern class TView* g_McAppUiActiveRenderContext_006A1AF4;

// Default absolute layout position (x, y) used when a control has no owner context, in
// the position-propagation pass (TView::vmethod_0089).
extern int g_McAppUiDefaultPosX_006A1A60;
extern int g_McAppUiDefaultPosY_006A1A64;

// Mouse-capture drag/repeat state used by TControl's input slots.
extern TMouseCaptureState g_McAppMouseCaptureState;        // 0x6a1a68
extern unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC; // 0x6a1adc

// Source-file path string ("D:\\Ambit\\McAppUI.cpp") passed with a line number to the
// UI invalidation-flag assert/log helper.
extern char g_szMcAppUiSourcePath_006950B0[];
extern char g_szQuickDrawSourcePath_00695168[];

// Source-file path string ("D:\\Ambit\\McWindow.cpp") for CMcWindow's one-shot asserts,
// and the gate read before the unknown-wParam 0x468 assert fires.
extern char g_szMcWindowSourcePath_006950D8[];
extern int g_nMcWindowStateMsgAssertGate_006A1C74;

// Source-file path string ("D:\\Ambit\\IncludeView.cpp") for CIncludeView's one-shot
// asserts, and the gate read before the msg-0x4ef detach assert fires.
extern char g_szIncludeViewSourcePath_00694D10[];
extern int g_nIncludeViewAssertGate_006A17B0;
extern int g_nIncludeViewPointerAssertGate_006A17C4;

// Header path string ("D:\\Ambit\\McAppUI.h") passed with a line number to city-production
// dialog assert/log helpers on the TControl branch.
extern char g_szMcAppUiHeaderPath_006943CC[];

// Placeholder strings baked into the turn-event dialog builders (season/treasury/info
// text shown until real values are bound).
extern char g_szUiPlaceholderStaticText_00694354[];
extern char g_szUiPlaceholderTreasury_006943B0[];
extern char g_szUiPlaceholderSeason_006943BC[];
extern char g_szUiPlaceholderSampleText_00694A98[];
// Provisional flag (0x00694c50) selecting the CDib blit path in TDDTemplateDialog::OnPaint.
extern int g_useCompatibleBitmapBlit;
// New-game setup screen (turn event 0x5dd) placeholder label strings.
extern char g_szNewGameAllAutoGPs_006949E0[];
extern char g_szNewGameNamesRandom_006949F0[];
extern char g_szNewGameNamesHistorical_006949F8[];
extern char g_szNewGameNamesLabel_00694A08[];
extern char g_szNewGameDifficultySetting_00694A10[];
extern char g_szNewGameDifficultyNighOnImpossible_00694A28[];
extern char g_szNewGameDifficultyHard_00694A40[];
extern char g_szNewGameDifficultyNormal_00694A48[];
extern char g_szNewGameDifficultyEasy_00694A50[];
extern char g_szNewGameDifficultyIntroductory_00694A58[];
extern char g_szNewGameScenarioPlaceholderTitle_00694A68[];
extern char g_szNewGameGameNameLabel_00694A88[];
extern char g_szUiPlaceholderZero_00694378[];
extern char g_szUiOrdersLabel_006948A4[];
extern char g_szUiDefaultPlanetName_00694528[];
extern char g_szUiPickAPlanet_00694530[];
extern char g_szUiAsEstimatedBy_00694540[];
extern char g_szUiForeignShippingObserved_00694554[];
extern char g_szUiHalfDozenShips_00694574[];
extern char g_szUiNavalForcesReportOf_006945A4[];
extern char g_szUiPlaceholderPont_006945C8[];
extern char g_szUiForeignFleetReport_006945D0[];
extern char g_szUiTraderIndiamen_006945EC[];
extern char g_szUiStoppedFromTrade_00694608[];
extern char g_szUiPlaceholderPokei_0069463C[];
extern char g_szUiToLabel_00694644[];
extern char g_szUiItemLabel_00694648[];
extern char g_szUiCarryingCargoOf_00694650[];
extern char g_szUiOwnrTag_00694668[];
extern char g_szUiMerchantsBelongingTo_00694670[];
extern char g_szUiAndConsistingOf_0069468C[];
extern char g_szUiByTaskForceCommandedBy_006946A4[];
extern char g_szUiAdmiralKirk_006946C8[];
extern char g_szUiInThe_006946FC[];
extern char g_szUiSeaOfOblongata_00694704[];
extern char g_szUiThreeVessels_00694718[];
extern char g_szUiResultOfSuccessful_00694724[];
extern char g_szUiBlockadeLabel_00694744[];
extern char g_szUiEnemyTradeInterrupted_00694750[];
extern char g_szUiSeaOfSalamanders_0069476C[];
extern char g_szUiEngageAllFloating_0069478C[];
extern char g_szUiForceCurrentlyLocated_006947B0[];
extern char g_szUiTaskForceReport_006947D8[];
extern char g_szUiRegularsLabel_006947F0[];
extern char g_szUiSkirmishersLabel_006947FC[];
extern char g_szUiMinutemanLabel_0069480C[];
extern char g_szUiConstructionOptions_00694818[];
extern char g_szUiEditTextLabel_00694834[];
extern char g_szUiAdmiralBobMinnow_00694840[];
extern char g_szUiCompositionLabel_0069486C[];
extern char g_szUiPatrolTheWaters_0069487C[];
extern char g_szUiOneHenTwoDucks_006948AC[];
extern char g_szUiArmyReportTitle_006948E0[];
extern char g_szUiCivilianReportTitle_006948F0[];
extern char g_szUiLossesHaxaco_00694904[];
extern char g_szUiOrderOfBattle_00694930[];
extern char g_szUiHaxacoLegions_0069494C[];
extern char g_szUiSkirmishReportTitle_00694998[];
extern char g_szUiPage14of14_006949AC[];
extern char g_szUiPlaceholderOne_006943AC[];
extern char g_szUiAvailableColon_006949C8[];
extern char g_szUiCostColon_006949D8[];
extern char g_szUiUniversityTitle_00694B20[];
extern char g_szUiThousandDollars_00694B30[];
extern char g_szUiLevel1_00694B38[];
extern char g_szUiPlaceholder185_00694ABC[];
extern char g_szUiQuantityToOfferLabel_00694AC0[];
extern char g_szUiAvailableLabel_00694AD8[];
extern char g_szUiPriceLabel_00694AE4[];
extern char g_szUiCommodityLabel_00694AEC[];
extern char g_szUiBoardOfTradeLabel_00694AF8[];

// Source-file path string ("D:\\Ambit\\Cross\\UGameWindow.cpp") passed with a line number to
// the UI invalidation-flag assert helper from the TDlgWindow/UGameWindow assert hooks.
extern char g_szUGameWindowSourcePath_00696bc0[];

// Source-file path string ("D:\\Ambit\\Cross\\UCountry.cpp") passed with a line number to
// the UI invalidation-flag assert helper from TGreatPower nil-pointer assert hooks.
extern char g_szUCountrySourcePath_00696728[];

// Gate checked by TControl::AssertCityProductionGlobalStateInitialized before the
// McAppUI.h line-0x56f assert path runs.
extern int g_McAppUiFlag_006A143C;

// Source path/gate for the USetupScreens.cpp line-0x2e6 assert in
// TNetSelectPicture::DoEvent (and siblings in that TU).
extern char g_szSetupScreensSourcePath_00698AB8[];
extern int g_SetupScreensAssertFlag_006A4264;

} // extern "C"

// Active root of the in-progress UI resource tree and the entry currently being registered.
extern TView* g_pUiResourceHead;
extern TView* g_pUiResourceContext;

// UDisplayMgr font literals and runtime CString slots (markers in global_data_tables.cpp).
extern "C" const char g_szUiFontLiteralBelweBdBt[];
extern "C" const char g_szUiFontLiteralPalatino[];
extern "C" const char g_szUiFontLiteralBelweLight[];
extern "C" const char g_szUiNilPointerMessage[];
extern "C" const char g_szDecimalFormat[]; // "%d" @ 0x69430c

// Great-power pressure tuning tables (see global_data_tables.cpp for values).
extern "C" const int g_anNationBasePressureByLocale[6];
extern "C" const int g_anGreatPowerPressureMinFloorByLocale[6];
extern "C" const int g_anGreatPowerEscalationSeedByLocale[6];
extern "C" const int g_anGreatPowerPressureRiseCapByLocale[6];
extern "C" const int g_anGreatPowerPressureDecayStepByLocale[6];
extern "C" const int g_anGreatPowerPressureRiseStepByLocale[6];
extern "C" const int g_anGreatPowerCompileThresholdByLocale[6];
extern "C" const int g_anGreatPowerPressureHardAlertThresholdByLocale[6];
extern "C" const int g_anNationStartingTreasuryByLocale[6];
extern POINT g_ptGreatPowerModalMessage; // @ 0x6a2df0
// Per-subsystem VPoint equivalents passed to the ModalMessage overloads. The Mac
// signatures provide the semantic type; Windows stores them as zero-initialized POINTs.
extern POINT g_ptArmyOrderModalMessage;               // @ 0x6a2318
extern POINT g_ptCityInteriorMinisterModalMessage;    // @ 0x6a2c18
extern POINT g_ptNationComparisonModalMessage;        // @ 0x6a3180
extern POINT g_ptTechItemModalMessage;                // @ 0x6a5820
extern POINT g_ptNationAwolModalMessage;              // @ 0x6a3d08
extern POINT g_ptLoungeNationReplacementModalMessage; // @ 0x6a3d98
extern POINT g_ptMapModeModalMessage;                 // @ 0x6a45c0
extern POINT g_ptTacticalAutoPlayModalMessage;        // @ 0x6a4650
extern POINT g_ptTechCapabilityModalMessage;          // @ 0x6a57c8
extern POINT g_ptUiPromptModalMessage;                // @ 0x6a5be0
extern POINT g_ptCitySiteSelectionDialogPlacement;    // @ 0x6a5b58
extern POINT g_ptQueryFloaterModalMessage;            // @ 0x6a4048
extern POINT g_ptDiplomacyNoticeModalMessage;         // @ 0x6a2fc0
extern POINT g_ptGameSetupModalMessage;               // @ 0x6a4218
extern int g_nationInfoGoldResourceOverride_006a5bac;
extern int g_lastTurnAlertTick_006a31c0;
extern int g_lastClickedMapTileIndex_006a4608;
extern int g_localizationAudioSlotCursor_006a60f8;
extern char g_szImpSaveExtension_00698708[];
extern char g_szMultiplayerSavePrefix_00698710[];
extern char g_szSingleSlotSavePrefix_00698718[];
extern char g_szLiteralRb_00698720[];
extern char g_szSaveDirectoryPrefix_00698724[];
extern char g_szLiteralA_0069872C[];
extern char g_szSavedDocumentMarker_0069B848[];
extern char g_szLoadedDocumentMarker_0069B854[];
extern const char* const g_pszSingleSlotSavePrefix_0065DDD0;  // "slot" @ 0x65ddd0
extern const char* const g_pszMultiplayerSavePrefix_0065DDD4; // "mult" @ 0x65ddd4
extern const char* const g_pszImpSaveExtension_0065DDD8;      // ".imp" @ 0x65ddd8
extern "C" char g_szClientSavePrefix_00697CBC[];
extern const char* const g_pszClientSavePrefix_0065BF5C; // "cli_" @ 0x65bf5c
extern char g_ScenarioSaveNameBuffer_006A2178[0x30];     // scenario name for save flow
extern POINT g_ptSaveLoadErrorModalMessage;
extern int g_saveDocumentAssertGuard;
extern char* g_pszDescriptorDefaultName_00653300;
extern char g_szUiCloseParen_006973C8[];
extern char g_szUiOpenParen_0069806C[];
extern POINT g_ptCivilianOrderModalMessage; // @ 0x6a2d40
extern "C" const char g_szUiFailureMessage[];
extern CString g_cstrUiFontBelweLight;
extern CString g_cstrUiFontPalatino;
extern CString g_cstrUiFontBelweBdBt;
extern int g_nUiInvalidationAssertFlagLine471;
extern int g_nUiInvalidationAssertFlagLine495;

// Zone status-code PRNG seed (0x6a5aec): reseeded from the scenario tag string hash at
// the start of RegenerateAllMapActionContextStatusCodes, then advanced by the LCG in
// GenerateZoneStatusCodeIfUnset (x = x*0x15a4e35 + 1).
extern unsigned int g_zoneStatusCodePrngSeed_006a5aec;
// Per-nation ordinal used while assigning province names from string-resource groups
// 8000 + nationSlot. GenerateProvinceNames resets all 23 entries before each pass.
extern "C" short g_anProvinceNameOrdinalByNationSlot_006a5af0[23];
// Map-action-context display-name cache key (0x6984b8): reset to -1 before each status
// regen pass; read/written by GenerateMapActionContextDisplayNameAndHeadline.
extern int g_mapActionContextDisplayNameCacheId_006984b8;
// Companion stride (0x6984bc) for the display-name cache key: a random step (1/7/0xb/0x17)
// added to the key after each headline resource pick.
extern int g_mapActionContextDisplayNameCacheStep_006984bc;

// Localized-label string-group indices, keyed by GetMapContextActionCode's return value
// (0..0x10 hold real tokens 0x3f0..0x3f8; the table is read by
// ActionCursor, 0x559dd0).
extern short g_awMapContextActionLabelTokenByCommand[17];

// Game singleton pointers (markers in global_data_tables.cpp).
extern TZone* g_pMapActionContextListHead;
extern TOcean* g_pActiveMapOrderContext;
// Resolved-context cache written by GetMapContextActionCode (0x559a70) for a downstream
// dialog branch; not yet consumed by any ported reader.
extern TTaskForce* g_pCachedMapActionContext;
extern TMapMgr* g_pGlobalMapState;
extern TCivMgr* g_pSelectedCivilianOrderState; // 0x6a43dc — the TCivMgr instance

// Seed viewport offsets copied into TWorldView::viewportOrigin60.x/Y by the TOceanDialog
// ctor; the only known writer (0x56a3b0) zeroes both.
extern int g_nOceanDialogSeedViewportOffsetX; // 0x6a3ff0
extern int g_nOceanDialogSeedViewportOffsetY; // 0x6a3ff4

// Map-dialog viewport width in tiles (0x51ac40 centers on a tile by column - span/2).
// int, not short: 0x51adf0 reads the full dword; word readers use static_cast<short>.
extern int g_wMapDialogViewportTileSpan; // 0x6a33b0

// Per-ability unit-order cost profile rows (see TUnitOrder::SetOrderCostProfile). 0x695cd0.
extern short g_aUnitOrderCostProfileByAbilityId[0x1e][7];
// Initial city recruitment profiles for order slots 0x22..0x2a. 0x695c50.
extern short g_aInitialCityRecruitmentOrderProfiles[9][7];

// Per-tech prerequisite pair (tech ids; 0 = none), indexed by tech id. 0x66ac10.
extern short g_aTechItemPrerequisitePairs[34][2];
// Per-tech research cost in gold, indexed by tech id. 0x66ad58.
extern int g_anTechItemResearchCostByTechId[29];

// Assert source-path strings for the UViewMgr TU family.
extern "C" const char s_SourcePathUViewMgr_0069B6BC[];
extern "C" const char s_SourcePathUMapDlog_006973D0[];
extern "C" const char s_SourcePathUNewspaper_00698470[];
extern "C" const char s_SourcePathUMultiplayerMgr_00698040[];
extern "C" const char s_SourcePathUNavy_006983C8[];
extern "C" const char s_SourcePathUTacViews_00699FF4[];
extern "C" const char s_SourcePathUViewMgrMore_0069B740[];
extern "C" const char s_SourcePathUHelpMgr_00696C58[];
// Assert source-path string for the UDefenseMinister TU.
extern "C" const char s_SourcePathUDefenseMinister_00696860[];
// Assert source-path string for the UArmyMgr TU.
extern "C" const char s_SourcePathUArmyMgr_0069573C[];
extern "C" const char s_SourcePathUCityDialogs_006962E8[];
extern "C" const char s_SourcePathUMacViewMgr_00696D68[];
extern "C" const char s_SourcePathUTestDialogs_0069A7F8[];
extern "C" const char s_SourcePathUCityViews_00696650[];
extern "C" const char s_SourcePathUArmyViews_00695858[];
extern "C" const char s_SourcePathUOceanViews_00698650[];
// Assert source-path string for the UCityMinister TU.
extern "C" const char s_SourcePathUCityMinister_006964B0[];
// Assert source-path string for the USuperMap TU (TMapUberPicture family).
extern "C" const char s_SourcePathUSuperMap_0069943C[];
// Assert source-path string for the UTradeViews TU (TOfferDeskPicture family).
extern "C" const char s_SourcePathUTradeViews_0069AA94[];
extern "C" const char s_SourcePathUOcean_006984CC[];
// Default viewport-marker-box width, shared by TMiniMapView/TacticalBattleView's own
// marker-box construction (assigned once via ftol() elsewhere; role beyond that isn't
// further recovered).
extern "C" short g_defaultMarkerBoxWidth_006a460c;
extern short g_awDiplomacyTradePolicyIconValueTable[7];
extern TSoundPlayer* g_pSfxPlaybackSystem;
extern TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry;
extern TApplication* g_pApplicationUiRootController;
extern int g_turnEventDialogAnchorPoint[2];
extern CPtrList g_LiveViewRegistry;
extern CPtrList g_ModalViewStack;

// ============================================================================
// UI runtime globals
// ============================================================================

int SetGlobalUiInvalidationFlagAndReturnPrevious(int newValue);
// Clear g_McAppUiActiveFlag_006950AC and return the previous value (0x489a90).
int ClearGlobalUiInvalidationFlagAndReturnPrevious();

// Read g_McAppUiActiveFlag_006950AC (0x489a70) — guard checked before any real painting.
int GetMcAppUiActiveFlag();

// ============================================================================
// bd cwa: globals that were locally re-declared via raw extern in a consumer
// .cpp instead of being declared here (see AGENTS.md's global_data_tables.h
// consolidation rule). Grouped by consumer cluster below.
// ============================================================================

extern "C" {
// ImperialismApp.cpp — registry key/section literals.
extern const char* const g_pRegistryCompanyKey_0063E038;
extern const char* const g_pRegistryAppKey_0063E03C;
extern const char* const g_pRegistryProfileAppName_0063E050;
extern const char* const g_pRegistrySettingsSection_0063E040;
extern const char* const g_pRegistrySettingsSectionAlt_0063E044;
extern const char* const g_pRegistryAutoResKey_0063E048;
extern const char* const g_pRegistryLanguageKey_0063E04C;

// Shared empty-string literal (ImperialismApp/TCountry/TIncludeView/
// TLowDiskWarningDialog/TModuleLibraryCacheTableStateB/TSimMgr).
extern char g_szEmptyString[];
extern const char* const g_pszEmptyTextPointer_00656f60; // = g_szEmptyString @ 0x656f60

// TArmyMission.cpp / TNavyMission.cpp — shared per-hop/per-province distance decay
// weights (1.0, 0.8, ...), used by both army and navy mission scoring.
extern const float g_MissionOrderDistanceDecayWeightTable_006978c8[6];
extern float g_ArmyMissionDotProductWeights_00697980[5];
extern float g_ArmyMissionCandidateScoreTable_006978f8[];

// TAutoGreatPower.cpp — SetTradeOffersFor scaling constants.
extern double g_DAT_00653fc0_Value_00653FC0;             // 1/255
extern double g_DAT_00653fc8_Value_00653FC8;             // 32767.0
extern double g_Evaluate_Advisory_Case11_Value_00653FD8; // 0.5

// TCivMgr.cpp — engineer construction cost tables.
extern short g_awEngineerFortBuildCostByLevel[5];
extern int g_adwEngineerRailBuildCostByTerrainType[kStrategicTerrainCount];
// Civilian work-order rescind refund by cost class.
extern int g_adwCivilianWorkOrderCostByClass[16];

// TControl.cpp — UI resource entry default text-style/command-param block (also
// TMyStaticText.cpp/TStaticText.cpp).
extern TextStyle g_UiResourceEntryDefaultTextStyle;

// TControlSeaZoneMission.cpp / TDefendProvinceMission.cpp / TNavyMission.cpp —
// defend-province / mission priority-vector normalization constants.
extern const float g_AttackProvinceMissionReadinessThreshold_0065A8F0;
extern const float g_DefendProvinceMissionCrossSupportFloorScale_0065A8F8;
extern const float g_NavyMissionQueuedWeightDeficitScale_0065A958;
extern const float g_InvadeMissionSuppressedPriorContributionScale_0065A95C;
extern const float g_NavyMissionSimilarityExcessBlend_0065A960;
extern const float g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel_0065A968[5][4];
extern const float g_Recompute_Nation_Order_LookupTable_0065A9BC;
extern const float g_Recompute_Nation_Order_LookupTable_0065A9C4;
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern const float g_MissionPositiveFallback_0065A9B8;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9E0;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern const double g_PortZoneFriendlyMissionScoreMultiplier_0065AA10;
extern const double g_PortZoneForeignMissionScoreMultiplier_0065AA18;
extern const float g_Recompute_Nation_Order_LookupTable_0065AA20;
extern const double g_ArmyMissionEligibleUnitStrengthScale_0065AA48;
extern const float g_MissionResourceWeightScale_0065A8FC;
extern const float g_BlockadePortMissionThreatFloor_0065A900;
extern const float g_BlockadePortMissionThreatScale_0065A904;
extern const float g_MissionEmptyResourceWeight_0065AA24;
extern short g_awTacticalCompositionReferenceProfiles_00697870[];
extern short g_Populate_Beachhead_Mission_LookupTable_00697958[];
// TShip.cpp — per-category target-percentage weights (40/30/30/0) used by
// ComputeNavyOrderDistributionScoreForNation's divergence-score formula. Read via
// sign-extend (movsx) in the original despite being small positive values, so the
// storage type must be signed short to match the codegen.
extern const short g_NavyOrderDistributionCategoryWeights_00697978[4];
// TBeachheadMission.cpp — normalization base for the parent invade mission's
// calculated priority contribution.
extern const double g_BeachheadMissionPriorityNormalization_0065AA30;

// TMapMgr.cpp — per-resourceType requirement level table (0x513610).
extern unsigned char g_abUniversityRequirementLevelById[24][4];
// TUniversityView.cpp — TUniversityView::Draw (0x4cbf70) reads
// table[row + fielda4*4] (row 0-4, only the low 16 bits used, -1 = empty slot) to pick
// which resource's requirement row to draw for the selected recruitment category
// (fielda4). Real category boundaries/count not otherwise recovered; declared to the
// extent read (30 dwords @ 0x651030, raw-read from the binary since this region was
// previously unclaimed).
extern int g_UniversityRequirementResourceTypeTable[30];
extern unsigned char g_abResourceTypeUsesHighNibbleFlag[24];
// TMapMgr.cpp — per-resourceType capability-category code, compared for equality against
// a caller-supplied category code by FindMaxResourceCapabilityValueForTile (0x513720).
extern unsigned char g_abResourceTypeCapabilityCategory[24];
extern unsigned char g_abResourceTypeMiniCivMentionFlag[24];
// TMapMgr.cpp — per-resourceType required-order-type code (short), compared against
// pCivilianOrderEntry->orderType by SeedRecruitSearchVisitedStateByCapabilityThresholdAlt
// (0x515890).
extern short g_anResourceTypeRequiredOrderType[24];
// TMapMgr.cpp — per-resourceType "always-qualifies" flag; same caller as above.
extern unsigned char g_abResourceTypeAlwaysQualifies[24];
// TMapMgr.cpp — per-gateFlag eligibility flag (only indices 0-3 meaningful, gateFlag's
// range); same caller as above.
extern unsigned char g_abGateFlagQualifies[24];

// TMapMgr.cpp — hex-area neighbor lookup tables.
extern short g_Build_Hex_Area_LookupTable_00696E70[];
extern short g_Build_Hex_Area_LookupTable_00696E80[];

// TMapMgr.cpp — per-StrategicTerrainKind capability table at 0x00696f08, read by
// MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA for both the origin tile and each
// of its hex neighbors. Technology checks update its Hills, Mountain, and Swamp elements;
// the old model incorrectly split those three bytes into standalone flag globals.
extern unsigned char g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainCount];

// TMapMgr.cpp — per-StrategicTerrainKind priority score, read by
// TMapMgr::UpdateTilePrimaryAndSecondaryNeighborLinksByPriority (0x50fca0) to rank same-city
// hex neighbors when picking primaryNeighborTileIndex40/secondaryNeighborTileIndex3e. Indexed
// all eight strategic terrain kinds; read raw at 0x00696e10.
extern short g_anStrategicTerrainNeighborLinkPriority[kStrategicTerrainCount];

// TMapMgr.cpp — running region-marker id, assigned to a tile's regionSubtypeTag05 by
// TMapMgr::FloodFillTileRegionMarker (0x5143d0) and incremented (low 16 bits only) after each
// call. Read raw at 0x00696d90 (initial value 1).
extern int g_nNextRegionMarkerId;

// TMapMgr.cpp — per-tile sprite-variant bitmap-strip offset tables, indexed
// [gateFlag][spriteVariantIndex01] (table39 by spriteVariantIndex01 alone). Read by the
// rendering-variant lookup family (0x516150/0x5161a0/0x5161e0/0x516220).
extern short g_awTileSpriteVariantOffsetTable38[16][2];
extern short g_awTileSpriteVariantOffsetTable39[8];
extern short g_awTileSpriteVariantOffsetTable3a[16][5];
extern short g_awTileSpriteVariantOffsetTable3b[16][2];

// TMinor.cpp — ApplyIndexedResourceDeltaAndAdjustNationTotals scale constant.
extern float g_ApplyIndexedResourceDeltaScale_00653728;

// TMission.cpp — default mission score constant.
extern const float g_MissionDefaultScore_0065a468;
extern const double g_MissionScoreOneConstant_0065a470;
// TGreatPower_AssignTrackedEntryActions.cpp — same conceptual constants as the
// 0x65a468/0x65a470 pair above (0.0f mul/div selector, 1.0 "remaining priority" base)
// but distinct address instances read by 0x4eb8b0's inline scoring, plus a third 0.0
// (double) threshold used for the score-positivity checks there.
extern const float g_MissionDefaultScore_006545d0;
extern const double g_AiPressureUnsetSentinel_006545c8;
extern const float g_DefenseMinisterWeightZero_006548E0;
extern const double g_MinisterWeightHalf_006548E8;
extern const double g_MinisterWeightOne_006548F0;
extern const double g_BismarckWeightHigh_006548F8;
extern const double g_BismarckWeightLow_00654900;
extern const float g_DefenderMinisterWeight_00654908;
extern const double g_BullyWeightLow_00654910;
extern const double g_BullyWeightHigh_00654918;

extern const float g_UnreferencedConstant_006545d4;
extern const double g_MissionScoreOneConstant_006545d8;
extern const float g_AiPressureRatioCap_006545e0;
extern const double g_AiPressureMidpointScale_006545e8;
extern const float g_AiPressurePeerScale_006543e8;
extern const double g_MissionScoreZeroThreshold_006545f0;
extern const double g_MissionEligibilityRatioMargin_006545f8;
extern const float g_HexHighlightScreenScale_00658640;
extern float g_TileHeatmapNeighborDiffusionFactor;
extern double g_MapPreviewScaleX6A3410;
extern double g_MapPreviewScaleY6A33D0;
// Strategic-map screen-coordinate conversion scales (1/64). MSVC500 emits their
// dynamic initializers at 0x519910/0x519940, matching the original BSS-backed globals.
extern double g_mapCellRowScale_006a3360;
extern double g_mapCellColumnScale_006a3388;
extern double g_ScaleDefault6A1FE8;
extern double g_ScaleDefault6A1FC0;
extern int g_ResetStateDword6A1E20;
extern int g_ResetStateDword6A1E24;
extern int g_ResetStateDword6A1E48;
extern int g_ResetStateDword6A1E4C;
extern int g_ResetStateDword6A1E70;
extern int g_ResetStateDword6A1E74;
extern int g_ResetStateDword6A1F38;
extern int g_ResetStateDword6A1F3C;
extern short g_NavyResolveOrderRanking[14];
extern short g_NavyMissionOrderRanking[14];
extern short g_NavyPriorityOrderRanking[14];

// TSimMgr.cpp — per-nation scenario setup source table.
// Seven default nation setup rows: {control mode, city minister policy,
// foreign minister policy, defense minister policy}. 0x698b18.
extern short g_aDefaultNationSetupPolicyProfiles[7][4];

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp — debug tag literal passed to
// TSimMgr::RebuildMapContextAndGlobalMapState.
extern const char s_Chunk_00698C0C[];

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp / turn_flow_cooldown.cpp — turn-cooldown state.
extern short g_nTurnCooldownDeferCounter006A43C4;
extern short g_nTurnCooldownSideFlag00698B10;
extern "C" char g_bTurnFlowBootstrapComplete;
extern "C" char g_bMultiplayerScenarioSetupActive;
extern "C" const char s_PictWvGobPathFormat_00698BF4[];
extern "C" const char s_TurnEventCursorNameFormat_0069B6B4[];
extern "C" const char s_GameName_00698010[];
extern "C" const char s_PlayerName_0069801c[];

// THelpMgr.cpp — periodic nation-comparison advisory tick.
extern short g_nTurnFlowNationComparisonAdvisoryTick;

// TStatusButton.cpp / TCivDescription.cpp — city-dialog legend selection state.
extern void* g_pActiveCityDialogLegendSelectionOwner;
extern int g_bCityDialogLegendSelectionInitialized;

// TCivDescription.cpp — per-civilian-class tile profile / legend selection counts.
extern short g_anTargetTileProfileByCivilianClassAndSlot[];
extern unsigned short g_awCivilianLegendSelectionCountsBySlot[16];

// TArmyToolbar.cpp — maps each of the 30 military-unit types to one of the ten
// toolbar placard/arrow categories.
extern int g_anArmyToolbarCategoryByUnitType[30];

// TZone.cpp — zone-graph BFS distance cache (see bd 1uj.16).
extern int g_nMapActionContextCount;
extern void* g_pMapActionContextDistanceCache;
extern int g_nMapActionContextDistanceCacheSizedFor;

// TGameSetupPicture.cpp — main-menu 'rand' button developer cheat gate: holding shift
// while clicking only takes the instant-random-map shortcut when this flag is set
// (never toggled anywhere in the reachable game code -- likely a build-time/debug-only
// switch in the retail binary). 0x6a42dc.
extern unsigned char g_bRandomMapDeveloperCheatFlag;
// "Conan" — developer-cheat probe filename statted by TSimMgr::InitializeTurnFlowStateDefaults.
extern char g_szConanCheatFileName_00698BEC[];
} // extern "C"

// Per-nation-variant mapped flavor-text table (mapped_flavor_text.cpp / global_data_tables.cpp).
struct MappedFlavorTextNationVariantEntry {
  short variantIndex;
  short pad;
};
extern "C" MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32];

// UMapper coastline/region overlay tables (defined in global_data_tables.cpp): the
// per-tile-edge Seapoint quad table and the region-border SeaSegment table the merge pass
// consumes. Forward-declared so this header need not pull in sea_geometry.h; consumers that
// use the tables include it themselves.
class SeapointStretch;
class SeaSegmentStretch;
extern SeapointStretch g_seapointQuadTable_006a3478;
// Scratch remap from pre-existing city-region id to compact id. The load-map form of
// TMapMaker::MapGenFinalizePassSlot19 clears all 256 entries to -1 before populating it.
extern int g_cityRegionIdRemapTable_006a3498[0x100];
extern SeaSegmentStretch g_regionBorderLinkTable_006a3900;

// Hex-neighbour offset tables (offset-coordinate grid; even/odd rows shift columns
// differently), indexed by direction 0..5. Read by the city-region border/merge passes.
extern const int g_anTechItemPurchaseCostBySlot_0066aae8[34];
extern const int g_hexColOffsetEvenRow_00697450[6];
extern const int g_hexRowOffset_00697468[6];
extern const int g_hexColOffsetOddRow_00697480[6];
// Coarse 27x15 region-grid neighbour deltas. These are a second set of the same
// offset-coordinate hex directions used by TMapMaker::GetAdjacentRegionGridCell.
extern const int g_coarseHexColOffsetEvenRow_00697498[6];
extern const int g_coarseHexRowOffset_006974b0[6];
extern const int g_coarseHexColOffsetOddRow_006974c8[6];

// Per-hex-direction adjacency bit masks (1,2,4,8,16,32), indexed by direction 0..5. Read
// byte-wise (OR'd into per-tile adjacency mask bytes) by the tile-adjacency update pass.
extern const unsigned short g_hexDirectionBitMasks_00696e40[6];

// Second copy of the per-hex-direction adjacency bit mask table (1,2,4,8,16,32,0), indexed
// by direction 0..6 (index 6 is an unused trailing zero); read byte-wise into
// TTerrainStateRecordView::adjacencyBits06 by SetHexAdjacencyDirectionFlagsForTilePair.
extern const unsigned short g_hexDirectionBitMasksAlt_00696ea8[7];

// Map-generation PRNG state (LCG: x = x*0x15a4e35 + 1) and the region-seed grid dimensions,
// shared by the city-region seeding/template passes.
extern unsigned int g_mapGenLcgState_006a38e8;
extern int g_regionSeedGridRows_006a38ec;
extern int g_mapGenDesertQuota_006a38bc;
extern int g_mapGenMountainQuota_006a3470;
extern int g_mapGenHillsQuota_006a38c0;
extern int g_mapGenForestQuota_006a38f8;
extern int g_mapGenSwampQuota_006a38e0;
extern int g_mapGenRiverCount_006a38e4;
extern const int g_riverConnectionTypeByDirectionPair_00697568[6][6];
extern int g_regionSeedGridCols_006a38f0;

// One-shot assert-suppression flags for the UMapper overlay-segment passes (0x006a3910 for the
// scanline fill, 0x006a3914 for the route rebuild).
extern int DAT_006a3910;
extern int DAT_006a3914;

// Private retail assert guards for TStream's McAppStream.cpp diagnostics.
extern int g_streamLine304AssertGuard;
extern int g_streamLine596AssertGuard;

// Map-context flavor-text string pool (see global_data_tables.cpp).
extern char s_szSpaceSeparator_00695794[];
extern "C" const char s_szLineBreak_00695880[8];
extern char s_szTurnHistorySeparator_00699320[];
extern char s_szCombatLossesHeading_00699324[];
// Enables the clipped vertical offset used by TMiniMapView's viewport marker.
extern unsigned char g_applyMiniMapVerticalClipOffset_006993e8;
extern char s_szTurnHistoryPrefix_0069b71c[];
extern char s_szAdmiralPrefix_0069578c[];
extern char s_szColonSeparator_00696b10[];
extern char s_mcflavor_00696674[];
extern char s_mcflavor_00696d10[];
extern char s_mcflavor_00697238[];
extern char g_szScriptFileName_006972f8[];
extern char g_szFmtZone_006972e8[];
extern char g_szFmtShip_006972d0[];
extern char g_szFmtArmy_006972bc[];
extern char g_szFmtCivi_006972ac[];
extern char g_szFmtPort_006972a0[];
extern char g_szFmtRail_00697294[];
extern char g_szFmtCapa_00697280[];
extern char g_szFmtLabo_00697268[];
extern char g_szFmtEmba_00697254[];
extern char g_szFmtYear_00697248[];
extern char s_mcflavor_006976e0[];

extern char s_mcflavor_00698b0c[];
extern char s_mcflavor_0069ab00[];
extern char s_mcflavor_0069ab04[];
extern char s_mcflavor_0069ab08[];
extern char s_mcflavor_0069ab0c[];
extern char s_mcflavor_0069ab10[];
extern char s_mcflavor_0069ab14[];
extern char s_mcflavor_0069ab18[];
extern char s_mcflavor_0069ab1c[];
extern char s_mcflavor_0069ab20[];
extern char s_mcflavor_0069ab24[];
extern char s_mcflavor_0069ab28[];
extern char s_mcflavor_0069ab2c[];
extern char s_mcflavor_0069ab30[];
extern char s_mcflavor_0069ab34[];
extern char s_mcflavor_0069ab38[];
extern char s_mcflavor_0069ab3c[];
extern char s_mcflavor_0069ab40[];
extern char s_mcflavor_0069ab44[];
extern char s_mcflavor_0069ab48[];
extern char s_mcflavor_0069ab4c[];
extern char s_mcflavor_0069ab50[];
extern char s_mcflavor_0069ab54[];
extern char s_mcflavor_0069ab58[];
extern char s_mcflavor_0069ab5c[];
extern char s_mcflavor_0069ab60[];
extern char s_mcflavor_0069ab64[];
extern char s_mcflavor_0069ab68[];
extern char s_mcflavor_0069ab6c[];
extern char s_mcflavor_0069ab70[];
extern char s_mcflavor_0069ab74[];
extern char s_mcflavor_0069ab78[];
extern char s_mcflavor_0069ab7c[];
extern char s_mcflavor_0069ab80[];
extern char s_mcflavor_0069ab84[];
extern char s_mcflavor_0069ab88[];
extern char s_mcflavor_0069ab8c[];
extern char s_mcflavor_0069ab90[];
extern char s_mcflavor_0069ab94[];
extern char s_mcflavor_0069ab98[];
extern char s_mcflavor_0069ab9c[];
extern char s_mcflavor_0069aba0[];
extern char s_mcflavor_0069aba4[];
extern char s_mcflavor_0069aba8[];
extern char s_mcflavor_0069abac[];
extern char s_mcflavor_0069abb0[];
extern char s_mcflavor_0069abb4[];
extern char s_mcflavor_0069abb8[];
extern char s_mcflavor_0069abbc[];
extern char s_mcflavor_0069abc0[];
extern char s_mcflavor_0069abc4[];
extern char s_mcflavor_0069abcc[];
extern char s_mcflavor_0069abd0[];
extern char s_mcflavor_0069abd4[];
extern char s_mcflavor_0069abd8[];
extern char s_mcflavor_0069abdc[];
extern char s_mcflavor_0069abe0[];
extern char s_mcflavor_0069abe4[];
extern char s_mcflavor_0069abe8[];
extern char s_mcflavor_0069abec[];
extern char s_mcflavor_0069abf0[];
extern char s_mcflavor_0069abf4[];
extern char s_mcflavor_0069abf8[];
extern char s_mcflavor_0069abfc[];
extern char s_mcflavor_0069ac00[];
extern char s_mcflavor_0069ac04[];
extern char s_mcflavor_0069ac08[];
extern char s_mcflavor_0069ac0c[];
extern char s_mcflavor_0069ac10[];
extern char s_mcflavor_0069ac14[];
extern char s_mcflavor_0069ac18[];
extern char s_mcflavor_0069ac1c[];
extern char s_mcflavor_0069ac20[];
extern char s_mcflavor_0069ac24[];
extern char s_mcflavor_0069ac28[];
extern char s_mcflavor_0069ac2c[];
extern char s_mcflavor_0069ac30[];
extern char s_mcflavor_0069ac38[];
extern char s_mcflavor_0069ac3c[];
extern char s_mcflavor_0069ac40[];
extern char s_mcflavor_0069ac44[];
extern char s_mcflavor_0069ac48[];
extern char s_mcflavor_0069ac4c[];
extern char s_mcflavor_0069ac50[];
extern char s_mcflavor_0069ac54[];
extern char s_mcflavor_0069ac58[];
extern char s_mcflavor_0069ac5c[];
extern char s_mcflavor_0069ac60[];
extern char s_mcflavor_0069ac6c[];
extern char s_mcflavor_0069ac74[];
extern char s_mcflavor_0069ac80[];
extern char s_mcflavor_0069ac88[];
extern char s_mcflavor_0069ac90[];
extern char s_mcflavor_0069ac98[];
extern char s_mcflavor_0069ac9c[];
extern char s_mcflavor_0069aca0[];
extern char s_mcflavor_0069aca4[];
extern char s_mcflavor_0069aca8[];
extern char s_mcflavor_0069acac[];
extern char s_mcflavor_0069acb0[];
extern char s_mcflavor_0069acb4[];
extern char s_mcflavor_0069acb8[];
extern char s_mcflavor_0069acbc[];
extern char s_mcflavor_0069acc0[];
extern char s_mcflavor_0069acc4[];
extern char s_mcflavor_0069acc8[];
extern char s_mcflavor_0069accc[];
extern char s_mcflavor_0069acd0[];
extern char s_mcflavor_0069acd4[];
extern char s_mcflavor_0069acd8[];
extern char s_mcflavor_0069acdc[];
extern char s_mcflavor_0069ace0[];
extern char s_mcflavor_0069ace4[];
extern char s_mcflavor_0069ace8[];
extern char s_mcflavor_0069acec[];
extern char s_mcflavor_0069acf0[];
extern char s_mcflavor_0069acf4[];
extern char s_mcflavor_0069acf8[];
extern char s_mcflavor_0069acfc[];
extern char s_mcflavor_0069ad00[];
extern char s_mcflavor_0069ad04[];
extern char s_mcflavor_0069ad0c[];
extern char s_mcflavor_0069ad14[];
extern char s_mcflavor_0069ad20[];
extern char s_mcflavor_0069ad24[];
extern char s_mcflavor_0069ad28[];
extern char s_mcflavor_0069ad2c[];
extern char s_mcflavor_0069ad30[];
extern char s_mcflavor_0069ad34[];
extern char s_mcflavor_0069ad38[];
extern char s_mcflavor_0069ad3c[];
extern char s_mcflavor_0069ad40[];
extern char s_mcflavor_0069ad44[];
extern char s_mcflavor_0069ad48[];
extern char s_mcflavor_0069ad4c[];
extern char s_mcflavor_0069ad50[];
extern char s_mcflavor_0069ad54[];
extern char s_mcflavor_0069ad58[];
extern char s_mcflavor_0069ad60[];
extern char s_mcflavor_0069ad68[];
extern char s_mcflavor_0069ad70[];
extern char s_mcflavor_0069ad78[];
extern char s_mcflavor_0069ad84[];
extern char s_mcflavor_0069ad8c[];
extern char s_mcflavor_0069ad90[];
extern char s_mcflavor_0069ad94[];
extern char s_mcflavor_0069ad98[];
extern char s_mcflavor_0069ad9c[];
extern char s_mcflavor_0069ada0[];
extern char s_mcflavor_0069ada4[];
extern char s_mcflavor_0069ada8[];
extern char s_mcflavor_0069adac[];
extern char s_mcflavor_0069adb0[];
extern char s_mcflavor_0069adb4[];
extern char s_mcflavor_0069adb8[];
extern char s_mcflavor_0069adbc[];
extern char s_mcflavor_0069adc0[];
extern char s_mcflavor_0069adc4[];
extern char s_mcflavor_0069adc8[];
extern char s_mcflavor_0069adcc[];
extern char s_mcflavor_0069add0[];
extern char s_mcflavor_0069add4[];
extern char s_mcflavor_0069add8[];
extern char s_mcflavor_0069addc[];
extern char s_mcflavor_0069ade0[];
extern char s_mcflavor_0069ade4[];
extern char s_mcflavor_0069ade8[];
extern char s_mcflavor_0069adec[];
extern char s_mcflavor_0069adf0[];
extern char s_mcflavor_0069adf4[];
extern char s_mcflavor_0069adf8[];
extern char s_mcflavor_0069adfc[];
extern char s_mcflavor_0069ae00[];
extern char s_mcflavor_0069ae04[];
extern char s_mcflavor_0069ae08[];
extern char s_mcflavor_0069ae0c[];
extern char s_mcflavor_0069ae10[];
extern char s_mcflavor_0069ae14[];
extern char s_mcflavor_0069ae18[];
extern char s_mcflavor_0069ae24[];
extern char s_mcflavor_0069ae30[];
extern char s_mcflavor_0069ae34[];
extern char s_mcflavor_0069ae38[];
extern char s_mcflavor_0069ae3c[];
extern char s_mcflavor_0069ae40[];
extern char s_mcflavor_0069ae44[];
extern char s_mcflavor_0069ae48[];
extern char s_mcflavor_0069ae4c[];
extern char s_mcflavor_0069ae50[];
extern char s_mcflavor_0069ae54[];
extern char s_mcflavor_0069ae58[];
extern char s_mcflavor_0069ae5c[];
extern char s_mcflavor_0069ae60[];
extern char s_mcflavor_0069ae64[];
extern char s_mcflavor_0069ae68[];
extern char s_mcflavor_0069ae6c[];
extern char s_mcflavor_0069ae70[];
extern char s_mcflavor_0069ae74[];
extern char s_mcflavor_0069ae78[];
extern char s_mcflavor_0069ae7c[];
extern char s_mcflavor_0069ae80[];
extern char s_mcflavor_0069ae84[];
extern char s_mcflavor_0069ae88[];
extern char s_mcflavor_0069ae90[];
extern char s_mcflavor_0069ae94[];
extern char s_mcflavor_0069ae98[];
extern char s_mcflavor_0069aea0[];
extern char s_mcflavor_0069aea8[];
extern char s_mcflavor_0069aeac[];
extern char s_mcflavor_0069aeb4[];
extern char s_mcflavor_0069aeb8[];
extern char s_mcflavor_0069aebc[];
extern char s_mcflavor_0069aec0[];
extern char s_mcflavor_0069aec4[];
extern char s_mcflavor_0069aec8[];
extern char s_mcflavor_0069aecc[];
extern char s_mcflavor_0069aed0[];
extern char s_mcflavor_0069aed4[];
extern char s_mcflavor_0069aed8[];
extern char s_mcflavor_0069aedc[];
extern char s_mcflavor_0069aee0[];
extern char s_mcflavor_0069aee4[];
extern char s_mcflavor_0069aeec[];
extern char s_mcflavor_0069aef8[];
extern char s_mcflavor_0069af00[];
extern char s_mcflavor_0069af08[];
extern char s_mcflavor_0069af0c[];
extern char s_mcflavor_0069af18[];
extern char s_mcflavor_0069af1c[];
extern char s_mcflavor_0069af20[];
extern char s_mcflavor_0069af24[];
extern char s_mcflavor_0069af28[];
extern char s_mcflavor_0069af2c[];
extern char s_mcflavor_0069af30[];
extern char s_mcflavor_0069af34[];
extern char s_mcflavor_0069af38[];
extern char s_mcflavor_0069af3c[];
extern char s_mcflavor_0069af40[];
extern char s_mcflavor_0069af44[];
extern char s_mcflavor_0069af48[];
extern char s_mcflavor_0069af4c[];
extern char s_mcflavor_0069af50[];
extern char s_mcflavor_0069af54[];
extern char s_mcflavor_0069af58[];
extern char s_mcflavor_0069af5c[];
extern char s_mcflavor_0069af60[];
extern char s_mcflavor_0069af64[];
extern char s_mcflavor_0069af68[];
extern char s_mcflavor_0069af6c[];
extern char s_mcflavor_0069af70[];
extern char s_mcflavor_0069af74[];
extern char s_mcflavor_0069af78[];
extern char s_mcflavor_0069af7c[];
extern char s_mcflavor_0069af80[];
extern char s_mcflavor_0069af84[];
extern char s_mcflavor_0069af88[];
extern char s_mcflavor_0069af8c[];
extern char s_mcflavor_0069af90[];
extern char s_mcflavor_0069af94[];
extern char s_mcflavor_0069af98[];
extern char s_mcflavor_0069af9c[];
extern char s_mcflavor_0069afa0[];
extern char s_mcflavor_0069afb0[];
extern char s_mcflavor_0069afc0[];
extern char s_mcflavor_0069afd0[];
extern char s_mcflavor_0069afdc[];
extern char s_mcflavor_0069afec[];
extern char s_mcflavor_0069aff4[];
extern char s_mcflavor_0069b004[];
extern char s_mcflavor_0069b010[];
extern char s_mcflavor_0069b01c[];
extern char s_mcflavor_0069b020[];
extern char s_mcflavor_0069b024[];
extern char s_mcflavor_0069b028[];
extern char s_mcflavor_0069b02c[];
extern char s_mcflavor_0069b030[];
extern char s_mcflavor_0069b034[];
extern char s_mcflavor_0069b038[];
extern char s_mcflavor_0069b03c[];
extern char s_mcflavor_0069b040[];
extern char s_mcflavor_0069b044[];
extern char s_mcflavor_0069b048[];
extern char s_mcflavor_0069b04c[];
extern char s_mcflavor_0069b050[];
extern char s_mcflavor_0069b054[];
extern char s_mcflavor_0069b058[];
extern char s_mcflavor_0069b05c[];
extern char s_mcflavor_0069b060[];
extern char s_mcflavor_0069b064[];
extern char s_mcflavor_0069b068[];
extern char s_mcflavor_0069b06c[];
extern char s_mcflavor_0069b070[];
extern char s_mcflavor_0069b078[];
extern char s_mcflavor_0069b07c[];
extern char s_mcflavor_0069b084[];
extern char s_mcflavor_0069b088[];
extern char s_mcflavor_0069b08c[];
extern char s_mcflavor_0069b090[];
extern char s_mcflavor_0069b098[];
extern char s_mcflavor_0069b09c[];
extern char s_mcflavor_0069b0a0[];
extern char s_mcflavor_0069b0a4[];
extern char s_mcflavor_0069b0a8[];
extern char s_mcflavor_0069b0ac[];
extern char s_mcflavor_0069b0b0[];
extern char s_mcflavor_0069b0b4[];
extern char s_mcflavor_0069b0b8[];
extern char s_mcflavor_0069b0bc[];
extern char s_mcflavor_0069b0c0[];
extern char s_mcflavor_0069b0c4[];
extern char s_mcflavor_0069b0c8[];
extern char s_mcflavor_0069b0cc[];
extern char s_mcflavor_0069b0d0[];
extern char s_mcflavor_0069b0d4[];
extern char s_mcflavor_0069b0d8[];
extern char s_mcflavor_0069b0dc[];
extern char s_mcflavor_0069b0e0[];
extern char s_mcflavor_0069b0e4[];
extern char s_mcflavor_0069b0e8[];
extern char s_mcflavor_0069b0ec[];
extern char s_mcflavor_0069b0f0[];
extern char s_mcflavor_0069b0f4[];
extern char s_mcflavor_0069b0f8[];
extern char s_mcflavor_0069b100[];
extern char s_mcflavor_0069b104[];
extern char s_mcflavor_0069b108[];
extern char s_mcflavor_0069b10c[];
extern char s_mcflavor_0069b110[];
extern char s_mcflavor_0069b114[];
extern char s_mcflavor_0069b118[];
extern char s_mcflavor_0069b11c[];
extern char s_mcflavor_0069b120[];
extern char s_mcflavor_0069b124[];
extern char s_mcflavor_0069b128[];
extern char s_mcflavor_0069b12c[];
extern char s_mcflavor_0069b130[];
extern char s_mcflavor_0069b134[];
extern char s_mcflavor_0069b138[];
extern char s_mcflavor_0069b13c[];
extern char s_mcflavor_0069b14c[];
extern char s_mcflavor_0069b158[];
extern char s_mcflavor_0069b15c[];
extern char s_mcflavor_0069b160[];
extern char s_mcflavor_0069b164[];
extern char s_mcflavor_0069b168[];
extern char s_mcflavor_0069b16c[];
extern char s_mcflavor_0069b170[];
extern char s_mcflavor_0069b174[];
extern char s_mcflavor_0069b178[];
extern char s_mcflavor_0069b17c[];
extern char s_mcflavor_0069b184[];
extern char s_mcflavor_0069b188[];
extern char s_mcflavor_0069b18c[];
extern char s_mcflavor_0069b190[];
extern char s_mcflavor_0069b194[];
extern char s_mcflavor_0069b198[];
extern char s_mcflavor_0069b19c[];
extern char s_mcflavor_0069b1a0[];
extern char s_mcflavor_0069b1a8[];
extern char s_mcflavor_0069b1ac[];
extern char s_mcflavor_0069b1b0[];
extern char s_mcflavor_0069b1b4[];
extern char s_mcflavor_0069b1b8[];
extern char s_mcflavor_0069b1bc[];
extern char s_mcflavor_0069b1c0[];
extern char s_mcflavor_0069b1c4[];
extern char s_mcflavor_0069b1cc[];
extern char s_mcflavor_0069b1d0[];
extern char s_mcflavor_0069b1d4[];
extern char s_mcflavor_0069b1d8[];
extern char s_mcflavor_0069b1dc[];
extern char s_mcflavor_0069b1e0[];
extern char s_mcflavor_0069b1e4[];
extern char s_mcflavor_0069b1e8[];
extern char s_mcflavor_0069b1ec[];
extern char s_mcflavor_0069b1f0[];
extern char s_mcflavor_0069b1f4[];
extern char s_mcflavor_0069b1f8[];
extern char s_mcflavor_0069b1fc[];
extern char s_mcflavor_0069b204[];
extern char s_mcflavor_0069b208[];
extern char s_mcflavor_0069b20c[];
extern char s_mcflavor_0069b210[];
extern char s_mcflavor_0069b214[];
extern char s_mcflavor_0069b218[];
extern char s_mcflavor_0069b21c[];
extern char s_mcflavor_0069b220[];
extern char s_mcflavor_0069b224[];
extern char s_mcflavor_0069b228[];
extern char s_mcflavor_0069b22c[];
extern char s_mcflavor_0069b234[];
extern char s_mcflavor_0069b238[];
extern char s_mcflavor_0069b23c[];
extern char s_mcflavor_0069b240[];
extern char s_mcflavor_0069b244[];
extern char s_mcflavor_0069b248[];
extern char s_mcflavor_0069b24c[];
extern char s_mcflavor_0069b254[];
extern char s_mcflavor_0069b25c[];
extern char s_mcflavor_0069b260[];
extern char s_mcflavor_0069b264[];
extern char s_mcflavor_0069b268[];
extern char s_mcflavor_0069b26c[];
extern char s_mcflavor_0069b270[];
extern char s_mcflavor_0069b274[];
extern char s_mcflavor_0069b278[];
extern char s_mcflavor_0069b27c[];
extern char s_mcflavor_0069b280[];
extern char s_mcflavor_0069b284[];
extern char s_mcflavor_0069b288[];
extern char s_mcflavor_0069b28c[];
extern char s_mcflavor_0069b290[];
extern char s_mcflavor_0069b294[];
extern char s_mcflavor_0069b298[];
extern char s_mcflavor_0069b29c[];
extern char s_mcflavor_0069b2a0[];
extern char s_mcflavor_0069b2a4[];
extern char s_mcflavor_0069b2a8[];
extern char s_mcflavor_0069b2ac[];
extern char s_mcflavor_0069b2b0[];
extern char s_mcflavor_0069b2b4[];
extern char s_mcflavor_0069b2b8[];
extern char s_mcflavor_0069b2bc[];
extern char s_mcflavor_0069b2c0[];
extern char s_mcflavor_0069b2c4[];
extern char s_mcflavor_0069b2c8[];
extern char s_mcflavor_0069b2cc[];
extern char s_mcflavor_0069b2d0[];
extern char s_mcflavor_0069b2d4[];
extern char s_mcflavor_0069b2d8[];
extern char s_mcflavor_0069b2dc[];
extern char s_mcflavor_0069b2e0[];
extern char s_mcflavor_0069b2e4[];
extern char s_mcflavor_0069b2e8[];
extern char s_mcflavor_0069b2f0[];
extern char s_mcflavor_0069b2f8[];
extern char s_mcflavor_0069b2fc[];
extern char s_mcflavor_0069b304[];
extern char s_mcflavor_0069b308[];
extern char s_mcflavor_0069b30c[];
extern char s_mcflavor_0069b310[];
extern char s_mcflavor_0069b314[];
extern char s_mcflavor_0069b318[];
extern char s_mcflavor_0069b31c[];
extern char s_mcflavor_0069b320[];
extern char s_mcflavor_0069b324[];
extern char s_mcflavor_0069b328[];
extern char s_mcflavor_0069b32c[];
extern char s_mcflavor_0069b334[];
extern char s_mcflavor_0069b338[];
extern char s_mcflavor_0069b33c[];
extern char s_mcflavor_0069b340[];
extern char s_mcflavor_0069b344[];
extern char s_mcflavor_0069b348[];
extern char s_mcflavor_0069b34c[];
extern char s_mcflavor_0069b350[];
extern char s_mcflavor_0069b354[];
extern char s_mcflavor_0069b358[];
extern char s_mcflavor_0069b35c[];
extern char s_mcflavor_0069b360[];
extern char s_mcflavor_0069b364[];
extern char s_mcflavor_0069b368[];
extern char s_mcflavor_0069b36c[];
extern char s_mcflavor_0069b370[];
extern char s_mcflavor_0069b374[];
extern char s_mcflavor_0069b378[];
extern char s_mcflavor_0069b37c[];
extern char s_mcflavor_0069b380[];
extern char s_mcflavor_0069b384[];
extern char s_mcflavor_0069b388[];
extern char s_mcflavor_0069b38c[];
extern char s_mcflavor_0069b390[];
extern char s_mcflavor_0069b394[];
extern char s_mcflavor_0069b398[];
extern char s_mcflavor_0069b39c[];
extern char s_mcflavor_0069b3a0[];
extern char s_mcflavor_0069b3a4[];
extern char s_mcflavor_0069b3a8[];
extern char s_mcflavor_0069b3ac[];
extern char s_mcflavor_0069b3b0[];
extern char s_mcflavor_0069b3b4[];
extern char s_mcflavor_0069b3b8[];
extern char s_mcflavor_0069b3bc[];
extern char s_mcflavor_0069b3c4[];
extern char s_mcflavor_0069b3c8[];
extern char s_mcflavor_0069b3cc[];
extern char s_mcflavor_0069b3d0[];
extern char s_mcflavor_0069b3d4[];
extern char s_mcflavor_0069b3dc[];
extern char s_mcflavor_0069b3e0[];
extern char s_mcflavor_0069b3e4[];
extern char s_mcflavor_0069b3e8[];
extern char s_mcflavor_0069b3ec[];
extern char s_mcflavor_0069b3f0[];
extern char s_mcflavor_0069b3f4[];
extern char s_mcflavor_0069b3f8[];
extern char s_mcflavor_0069b400[];
extern char s_mcflavor_0069b404[];
extern char s_mcflavor_0069b408[];
extern char s_mcflavor_0069b40c[];
extern char s_mcflavor_0069b410[];
extern char s_mcflavor_0069b418[];
extern char s_mcflavor_0069b41c[];
extern char s_mcflavor_0069b420[];
extern char s_mcflavor_0069b424[];
extern char s_mcflavor_0069b428[];
extern char s_mcflavor_0069b42c[];
extern char s_mcflavor_0069b430[];
extern char s_mcflavor_0069b434[];
extern char s_mcflavor_0069b438[];
extern char s_mcflavor_0069b43c[];
extern char s_mcflavor_0069b440[];
extern char s_mcflavor_0069b444[];
extern char s_mcflavor_0069b448[];
extern char s_mcflavor_0069b44c[];
extern char s_mcflavor_0069b454[];
extern char s_mcflavor_0069b458[];
extern char s_mcflavor_0069b45c[];
extern char s_mcflavor_0069b460[];
extern char s_mcflavor_0069b464[];
extern char s_mcflavor_0069b468[];
extern char s_mcflavor_0069b46c[];
extern char s_mcflavor_0069b470[];
extern char s_mcflavor_0069b474[];
extern char s_mcflavor_0069b478[];
extern char s_mcflavor_0069b47c[];
extern char s_mcflavor_0069b480[];
extern char s_mcflavor_0069b484[];
extern char s_mcflavor_0069b488[];
extern char s_mcflavor_0069b48c[];
extern char s_mcflavor_0069b490[];
extern char s_mcflavor_0069b498[];
extern char s_mcflavor_0069b49c[];
extern char s_mcflavor_0069b4a0[];
extern char s_mcflavor_0069b4a4[];
extern char s_mcflavor_0069b4a8[];
extern char s_mcflavor_0069b4ac[];
extern char s_mcflavor_0069b4b0[];
extern char s_mcflavor_0069b4b4[];
extern char s_mcflavor_0069b4b8[];
extern char s_mcflavor_0069b4bc[];
extern char s_mcflavor_0069b4c4[];
extern char s_mcflavor_0069b4c8[];
extern char s_mcflavor_0069b4cc[];
extern char s_mcflavor_0069b4d0[];
extern char s_mcflavor_0069b4d4[];
extern char s_mcflavor_0069b4d8[];
extern char s_mcflavor_0069b4dc[];
extern char s_mcflavor_0069b4e0[];
extern char s_mcflavor_0069b4e4[];
extern char s_mcflavor_0069b4e8[];
extern char s_mcflavor_0069b4ec[];
extern char s_mcflavor_0069b4f0[];
extern char s_mcflavor_0069b4f4[];
extern char s_mcflavor_0069b4f8[];
extern char s_mcflavor_0069b4fc[];
extern char s_mcflavor_0069b500[];
extern char s_mcflavor_0069b504[];
extern char s_mcflavor_0069b508[];
extern char s_mcflavor_0069b50c[];
extern char s_mcflavor_0069b510[];
extern char s_mcflavor_0069b514[];
extern char s_mcflavor_0069b518[];
extern char s_mcflavor_0069b51c[];
extern char s_mcflavor_0069b520[];
extern char s_mcflavor_0069b524[];
extern char s_mcflavor_0069b528[];
extern char s_mcflavor_0069b52c[];
extern char s_mcflavor_0069b534[];
extern char s_mcflavor_0069b53c[];
extern char s_mcflavor_0069b544[];
extern char s_mcflavor_0069b54c[];
extern char s_mcflavor_0069b554[];
extern char s_mcflavor_0069b55c[];
extern char s_mcflavor_0069b564[];
extern char s_mcflavor_0069b56c[];
extern char s_mcflavor_0069b57c[];
extern char s_mcflavor_0069b584[];
extern char s_mcflavor_0069b590[];
extern char s_mcflavor_0069b598[];
extern char s_mcflavor_0069b59c[];
extern char s_mcflavor_0069b5a4[];
extern char s_mcflavor_0069b5ac[];
extern char s_mcflavor_0069b5b8[];
extern char s_mcflavor_0069b5c0[];
extern char s_mcflavor_0069b5c4[];
extern char s_mcflavor_0069b5cc[];
extern char s_mcflavor_0069b5d4[];
extern char s_mcflavor_0069b5dc[];
extern char s_mcflavor_0069b5e4[];
extern char s_mcflavor_0069b5ec[];
extern char s_mcflavor_0069b5f4[];
extern char s_mcflavor_0069b5fc[];
extern char s_mcflavor_0069b604[];
extern char s_mcflavor_0069b60c[];
extern char s_mcflavor_0069b614[];
extern char s_mcflavor_0069b61c[];
extern char s_mcflavor_0069b624[];
extern char s_mcflavor_0069b628[];
extern char s_mcflavor_0069b630[];
extern char s_mcflavor_0069b638[];
extern char s_mcflavor_0069b640[];
extern char s_Data_scores_dat_0069b7fc[];
extern short g_creditsPlaybackActive_006a4084;
extern short g_offerDeskSelectionIndexTable_00668568[8];
// Persistent (X,Y) layout-capture buffer shared by the diplomacy popup family
// (TOffersPanelView::PoseOffer, TOffersPanelView::PoseWarOffer,
// InitializeDiplomacyMinisterActionControlsAndLabels) via TView::CaptureLayoutF0, which
// reads exactly buffer[0]/buffer[1] as ownerLocalX/ownerLocalY.
extern int g_diplomacyWarOfferSheetPosition_006a2fe0[2];
extern int g_diplomacyPopupLayoutPosition_006a3020[2];
// Zero origin used for the hidden dummy view installed by TInfoBarBehavior.
extern int g_InfoBarDummyOrigin_006A2410[2];
extern "C" const char s_SourcePathUDiplomacyViews_00696AE0[];
extern short g_MapOrderResourceRollWeightTable_0064c5d8[6][6];
// Need-type indices (into TGreatPower::needCurrentByType/needTargetByType), in priority
// order, that TInteriorMinister::MinisterSlot14 (0x4be520) tops up each turn while the
// nation still has need-cap headroom (needCapA6 - needsOverCapFlag).
extern short g_aInteriorMinisterNeedPriorityOrder_00696408[10];
extern short g_cityProductionReserveByPolicyBand_00696400[4];
extern float g_cityProductionUpgradeRatioThreshold_00696450[4];
extern short g_cityActionCapabilityGroupBySlot_00650670[32];
// Resource ids cleared before TPopulationMgr recomputes the three derived food needs.
extern "C" short g_cityPredictedNeedResetResourceIds[3];
extern "C" const float g_PopulationGrowthRateUnder10;
extern "C" const float g_PopulationGrowthRateUnder15;
extern "C" const float g_PopulationGrowthRateUnder20;
extern "C" const float g_PopulationGrowthRateUnder30;
extern "C" const float g_PopulationGrowthRateUnder40;
extern "C" const float g_PopulationGrowthRateUnder60;
extern "C" const float g_PopulationGrowthRateUnder80;
extern "C" const float g_PopulationGrowthRateUnder400;
extern "C" const double g_PopulationGrowthPenaltyPerRetry;
extern "C" const double g_PopulationGrowthMaximumRetryPenalty;
extern "C" const float g_PopulationGrowthRateAtOrAbove400;
// Reverse hit-test priority for the 16 city-production building regions.
extern short g_cityBuildingHitTestOrder[16];
// Per-building offset added to the city-building sound-effect base (3000).
extern short g_cityBuildingSoundCueOffsets[16];
extern "C" const char g_szCityProductionUniversityPrefix[];
extern "C" const char g_szCityProductionArmoryPrefix[];
extern "C" const char g_szCityProductionShipyardPrefix[];
// Naval combat damage-split ratios (TNavyTacUnit::ApplyTacticalDamageAndDeathState, 0x5a63c0):
// the two shares a hit's damage is divided between strength4 (hull) and crewStrength38
// depending on the attacker's ship-panel aim mode.
extern double g_dNavyDamageSplitRatioA_00669f10; // 0.25
extern double g_dNavyDamageSplitRatioB_00669f18; // 0.75
// Naval gunnery hit-chance formula constants (TNavyBattle::EvaluateAndResolveTactical-
// ActionAgainstTileOccupant, 0x5a5730): hitThreshold = quality*5 + 80/(ratio^3 + 1) where
// ratio = hexDistance / (range * 0.5).
extern double g_dNavyHitChanceRangeScale_00669ef8; // 0.5
extern float g_fNavyHitChanceCubeOffset_00669f00;  // -1.0
extern float g_fNavyHitChanceNumerator_00669f04;   // 80.0
