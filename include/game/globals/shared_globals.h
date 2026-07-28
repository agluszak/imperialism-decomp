#pragma once
// Cross-subsystem and unresolved global declarations. Definitions and address markers
// live in src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/city_ui/TCountry.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/nation/TMinor.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TView.h"
#include <afxtempl.h>
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_tags_common.h"

extern TInfoBarText* g_pCursorControlPanel;

// USmallViews.cpp shared empty-text pointer. The original stores a pointer to
// g_szEmptyString at 0x00662b90 and constructs transient CString values from it in
// TArmyInfoView and the strategic toolbar text-refresh paths.
extern "C" {
extern char* g_pSmallViewsEmptyText_00662B90;
}

extern TTradeMgr* g_pTradeMgr;

extern TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture006A4268;

// Shared substitution value read by TTradeTotalsView::Draw (0x5c1bd0) as
// the sole scanBracketExpressions() argument for its "balance" row template (GetString
// group 0x2740 idx 0x1b). The original's raw bytes are a compile-time-constant pointer
// to an empty string (not a deferred-construction CString), so this is modeled as a
// plain pointer aliasing the shared g_szEmptyString buffer, matching the
// g_pszEmptyTextRef_00669db8 idiom. Not yet pinned to a writer if one exists.
extern const char* g_cstrTradeTotalsBalanceSubstitution0066DB50;

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

extern TTechMgr* g_pTechMgr;

extern TSoundResourceManager g_soundResourceManager;

// Counts idle/audio-state polls before another random cue selection attempt.
extern short g_randomAudioCuePollCounter; // 0x006a4520

extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];

// Tactical unit facing-offset table (0x006a4780); see global_data_tables.cpp.
extern POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

extern TDisplayMgr* g_pDisplayMgr;

extern CPoint g_ptUiAnimatorSurfaceBounds; // 0x006a2228, initialized at 0x0049f000

extern unsigned char g_bStrategicMapSelectionOverlayPhase; // 0x006a224c

extern TMacViewMgr* g_pMacViewMgr;

extern TViewMgr* g_pViewMgr;

extern TAssetMgr* g_pAssetMgr;

extern TLanguageMgr* g_pLanguageMgr;

extern TAnimator* g_pUiAnimator;

// Active root of the in-progress UI resource tree and the entry currently being registered.
extern TView* g_pUiResourceHead;

extern POINT g_ptTechItemModalMessage; // @ 0x6a5820

extern POINT g_ptFormattedErrorModalMessage; // @ 0x6a5ab0

extern POINT g_ptLoungeNationReplacementModalMessage; // @ 0x6a3d98

extern POINT g_ptQueryFloaterModalMessage; // @ 0x6a4048

extern POINT g_ptGameSetupModalMessage; // @ 0x6a4218

extern int g_lastClickedMapTileIndex_006a4608;

extern int g_localizationAudioSlotCursor_006a60f8;

extern char g_szImpSaveExtension_00698708[];

extern char g_szMultiplayerSavePrefix_00698710[];

extern char g_szSingleSlotSavePrefix_00698718[];

extern char g_ScenarioSaveNameBuffer_006A2178[0x30]; // scenario name for save flow

extern char* g_pszDescriptorDefaultName_00653300;

extern char g_szUiCloseParen_006973C8[];

extern POINT g_ptCivilianOrderModalMessage; // @ 0x6a2d40

// Zone status-code PRNG seed (0x6a5aec): reseeded from the scenario tag string hash at
// the start of RegenerateAllMapActionContextStatusCodes, then advanced by the LCG in
// GenerateZoneStatusCodeIfUnset (x = x*0x15a4e35 + 1).
extern unsigned int g_zoneStatusCodePrngSeed_006a5aec;

// Game singleton pointers (markers in global_data_tables.cpp).
extern TZone* g_pMapActionContextListHead;

extern TOcean* g_pActiveMapOrderContext;

// Resolved-context cache written by GetMapContextActionCode (0x559a70) for a downstream
// dialog branch; not yet consumed by any ported reader.
extern TTaskForce* g_pCachedMapActionContext;

extern TMapMgr* g_pGlobalMapState;

extern TCivMgr* g_pSelectedCivilianOrderState; // 0x6a43dc — the TCivMgr instance

// Seed viewport offsets copied into TWorldView::viewportOrigin.x/Y by the TOceanDialog
// ctor; the only known writer (0x56a3b0) zeroes both.
extern int g_nOceanDialogSeedViewportOffsetX; // 0x6a3ff0

extern int g_nOceanDialogSeedViewportOffsetY; // 0x6a3ff4

// Per-ability unit-order cost profile rows (see TUnitOrder::SetOrderCostProfile). 0x695cd0.
extern short g_aUnitOrderCostProfileByAbilityId[0x1e][7];

// Per-tech research cost in gold, indexed by tech id. 0x66ad58.
extern int g_anTechItemResearchCostByTechId[29];

extern TSoundPlayer* g_pSfxPlaybackSystem;

extern TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry;

extern TApplication* g_pApplication;

extern const int g_hexColOffsetEvenRow_00697450[6];

extern const int g_hexRowOffset_00697468[6];

extern const int g_hexColOffsetOddRow_00697480[6];

// Map-generation PRNG state (LCG: x = x*0x15a4e35 + 1) and the region-seed grid dimensions,
// shared by the city-region seeding/template passes.
extern unsigned int g_mapGenLcgState_006a38e8;

extern int g_regionSeedGridRows_006a38ec;

extern int g_regionSeedGridCols_006a38f0;

// Map-context flavor-text string pool (see global_data_tables.cpp).
extern char s_szSpaceSeparator_00695794[];
extern char s_szGaugeCountSeparator_0069936C[];
extern "C" char s_szRankDotSeparator_00698ab4
    []; // ". " between high-score rank and name (defined in the extern "C" table block)
extern char s_szTurnSummaryIndent_00696790[]; // "      " @ 0x696790

extern char s_szTurnHistorySeparator_00699320[];

// Enables the clipped vertical offset used by TMiniMapView's viewport marker.
extern unsigned char g_applyMiniMapVerticalClipOffset_006993e8;

extern char s_szAdmiralPrefix_0069578c[];

extern char s_szColonSeparator_00696b10[];

extern char g_szLiteralWb_006976E0[];

extern char g_szLowercaseX[];

extern short g_creditsPlaybackActive_006a4084;

// Zero origin used for the hidden dummy view installed by TInfoBarBehavior.
extern int g_InfoBarDummyOrigin_006A2410[2];

// Need-type indices (into TGreatPower::needCurrentByType/needTargetByType), in priority
// order, that TInteriorMinister::SetCityPolicies (0x4be520) tops up each turn while the
// nation still has need-cap headroom (transportCapacity - reservedTransportCapacity).
extern short g_aInteriorMinisterNeedPriorityOrder_00696408[10];

// Naval combat damage-split ratios (TNavyTacUnit::ApplyNavalDamage, 0x5a63c0):
// the two shares a hit's damage is divided between strength4 (hull) and crewStrength38
// depending on the attacker's ship-panel aim mode.
extern double g_dNavyDamageSplitRatioA_00669f10; // 0.25

extern double g_dNavyDamageSplitRatioB_00669f18; // 0.75

// Naval gunnery hit-chance formula constants (TNavyBattle::EvaluateAndResolveTactical-
// ActionAgainstTileOccupant, 0x5a5730): hitThreshold = quality*5 + 80/(ratio^3 + 1) where
// ratio = hexDistance / (range * 0.5).
extern double g_dNavyHitChanceRangeScale_00669ef8; // 0.5

extern float g_fNavyHitChanceCubeOffset_00669f00; // -1.0

extern float g_fNavyHitChanceNumerator_00669f04; // 80.0

extern "C" {
extern "C" float g_fMissionScoreNormalizationDivisor;

extern "C" float g_fScatteredShipsMissionDefaultScore;

extern "C" short g_nArmsBasicResourceOfferSplitCount_006a3a54;

extern "C" short g_nArmsAdvancedResourceOfferSplitCount_006a3a58;

extern "C" IndustryCapabilityClassSlotEntry g_aIndustryCapabilityClassSlotTable[14];

// Cursor resource id by civilian-tile-order action code (12 entries).
extern short g_civilianTileOrderCursorTokenTable[];

// Per-unit-type tactical category code (slot 0x11 garrison sweep).
extern int g_anUnitTypeTacticalRangeByType_006699E8[30];

extern ArmyUnitCategoryStorage g_awTacticalUnitCategoryCodeBySlot[];

// Per-unit-type combat/composition class (0x695380), read by
// FormStacks when building a TArmyStack's
// field4/field6 composition code.
extern short g_awUnitCombatClassBySlot[32];

// The cached QuickDraw clip region — a heap CRgn built by the CRT static-init ctor
// at 0x494040 (ported in quickdraw_rendering.cpp as TQuickDrawClipStateInitializer).
// GetClip seeds from it; SetClip (0x495a30) copies a RgnHandle's region into it.
extern CRgn* g_pGlobalClipRegionHandleObject;

extern COLORREF g_QuickDrawForegroundColor;

extern char g_szQuickDrawFontFaceSystem[];

extern char g_szQuickDrawFontFaceBookAntiqua[];

extern char g_szQuickDrawFontFaceSmallFonts[];

extern int g_nQuickDrawOriginX;

extern int g_nQuickDrawOriginY;

// Left/top of the view-frame clip bounds used by TTacticalBattleView. Reset together by
// ResetUiFrameClipOrigin (0x005ad9e0). 0x6a5458/0x6a545c
extern int g_nUiFrameClipOriginX;

extern int g_nUiFrameClipOriginY;

extern TBitmapSurfaceContextDescriptor g_defaultQuickDrawSurfaceSentinel;

extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;

extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext;

extern TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext;

extern CDib* g_pColorKeyCompositeDib;

// Owner-nation tag (0..23) to the QuickDraw palette index used behind ocean-map
// order previews and garrison badges.
extern unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24];

// Per-owner outline palette used by the ocean overview's direct 16x16 neighbor-edge pass.
extern unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24];

// Secret garrison-close names used by the retail easter-egg path.
extern const char g_szGarrisonSecretNationNameFrog[];

extern const char g_szGarrisonSecretUnitNameSnidely[];

extern const unsigned char g_bDrawOceanRouteOverlay;

extern const unsigned char g_bTransferOceanViewportToActiveSurface;

extern const unsigned char g_bDrawOceanZoneLabels;

extern const unsigned char g_bDrawOceanNationLabels;

extern CDC* g_pQuickDrawMemoryDc;

extern const int g_pTradeSummarySelectionMap[23];

// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern TMinor* g_apSecondaryNationStateSlots[36];

// Original address 0x006a429c is g_apSecondaryNationStateSlots + 7: the 16 minor
// rows are an interior slice, not independent storage.
#define g_apNationAuxRuntimeStateSlots (g_apSecondaryNationStateSlots + 7)

extern TGreatPower* g_apNationStates[7];
// Several retail loops compare their cursor with the immediate one-past address
// 0x006a438c. It is not a separately allocated pointer object.
#define g_apNationStates_End g_apNationStates[7]

extern TSimMgr* g_pSimMgr;

extern THelpMgr* g_pHelpMgr;

extern TNewsMgr* g_pNewsMgr;

extern TAmbitApplication* g_pAmbitApplication;

extern const char* g_pszEmptyTextRef_00669db8;

// The multiplayer/game-flow singleton (0x6a43c8); every turn-event emitter is a
// __thiscall method on it (original callsites load ECX from here).
extern TMultiplayerMgr* g_pGameFlowState;

extern const char s_DataDirectoryPath_006942A8[];

extern const char s_IrgGlobPattern_006942FC[];

extern const char s_NoLanguageFilesMessage_006942B4[];

extern const char s_OutOfMemoryText_006941F0[];

extern const char s_ErrorCaption_00694204[];

extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;

extern TNavyMgr* g_pNavyOrderManager;

extern "C" TShip* g_pNavyPrimaryOrderListHead;

extern TArmyMgr* g_pMapContextActionManager;

extern char* g_pShipFractionSharedText_0065c830;

extern char* g_pStatusPictureMainSharedText_00668b88;

extern char* g_pLoungeLocalPlayerNameSharedText_0065c160;

extern int g_lastEdgeAutoScrollTick16;

extern int g_nSaveFormatVersion;

extern const short g_aDiplomacyPlanningQuarterPhaseByNation[7];

extern void (TSimMgr::* g_apfnScenarioScriptInstructionHandlers[27])(void*);

extern char g_szLiteralL_00694250[];

extern char g_szCmdSwitchLangQuit_00694254[];

extern ImperialismApp* g_pImperialismApp;

extern _PNH g_pfnPreviousNewHandler;

// Read only by ImperialismApp's developer assert command; no writer exists in the retail
// image, so the command deliberately exercises the nil-pointer assert path.
extern void* g_pAmbitDeveloperAssertProbe_006A1358;

extern short g_industryActionCostWeightResCode10[16];

extern AiCityActionCostProfile g_aiCityActionCostProfiles[30];

extern char g_szListSeparator_00695760[];

extern char g_szPlusPrefix_00698494[];

extern char g_szListConjunction_00698498[];

extern TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;

// Cached CCommandLineInfo::m_bShowSplash (cmdInfo+0x04), not m_nShellCommand.
extern BOOL g_cachedShowSplashFlag;

extern LPCSTR g_apFontFiles[];

extern void* g_pScopedMapQuickDrawViewContext;

extern CDC* g_pScopedMapQuickDrawDcHandleObject;

extern int g_nRandomMapSelectedNationSlot00698AB0;

extern char g_szCountryNameProfileKey00698AE0[];

extern "C" short g_aTradeDealCategoryOrder_0066D810[0x11];

extern "C" const double g_TradePowerIdentity_0066D8E0;

extern "C" const short g_aTradeItemBasePriceByCategory_0069A910[0x11];

extern "C" short g_infoPanelLabelXByRow_006969b0[4];

extern "C" short g_infoPanelLabelYByRow_006969c0[4];

extern "C" COLORREF g_defaultDropShadowTextColor;

// Placeholder strings baked into the turn-event dialog builders (season/treasury/info
// text shown until real values are bound).
extern char g_szUiPlaceholderStaticText_00694354[];

extern char g_szUiPlaceholderTreasury_006943B0[];

extern char g_szUiPlaceholderSeason_006943BC[];

extern char g_szUiPlaceholderSampleText_00694A98[];

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

extern "C" const char g_szUiNilPointerMessage[];

extern "C" const char g_szDecimalFormat[]; // "%d" @ 0x69430c

extern "C" char g_szClientSavePrefix_00697CBC[];

extern "C" const char g_szUiFailureMessage[];

// Per-nation ordinal used while assigning province names from string-resource groups
// 8000 + nationSlot. GenerateProvinceNames resets all 23 entries before each pass.
extern "C" short g_anProvinceNameOrdinalByNationSlot_006a5af0[23];

// Assert source-path strings for the UViewMgr TU family.
extern "C" const char s_SourcePathUViewMgr_0069B6BC[];

// Assert source-path string for the UTradeViews TU (TOfferDeskPicture family).
extern "C" const char s_SourcePathUTradeViews_0069AA94[];

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

extern int g_adwEngineerRailBuildCostByTerrainType[kStrategicTerrainCount];

// TControlSeaZoneMission.cpp / TDefendProvinceMission.cpp / TNavyMission.cpp —
// defend-province / mission priority-vector normalization constants.
extern const float g_AttackProvinceMissionReadinessThreshold_0065A8F0;

extern const float g_DefendProvinceMissionCrossSupportFloorScale_0065A8F8;

extern const float g_NavyMissionQueuedWeightDeficitScale_0065A958;

extern const float g_NavyMissionSimilarityExcessBlend_0065A960;

extern const float g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel_0065A968[5][4];

extern const float g_Recompute_Nation_Order_LookupTable_0065A9BC;

extern const float g_Recompute_Nation_Order_LookupTable_0065A9C4;

extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;

extern const float g_MissionPositiveFallback_0065A9B8;

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

// TBeachheadMission.cpp — normalization base for the parent invade mission's
// calculated priority contribution.
extern const double g_BeachheadMissionPriorityNormalization_0065AA30;

// TMapMgr.cpp — per-resourceType requirement level table (0x513610).
extern unsigned char g_abUniversityRequirementLevelById[24][4];

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

// TMinor.cpp — ApplyIndexedResourceDeltaAndAdjustNationTotals scale constant.
extern float g_ApplyIndexedResourceDeltaScale_00653728;

// TMission.cpp — default mission score constant.
extern const float g_MissionDefaultScore_0065a468;

extern const double g_MissionScoreOneConstant_0065a470;

extern const double g_MinisterWeightHalf_006548E8;

extern const double g_MinisterWeightOne_006548F0;

extern const double g_BismarckWeightHigh_006548F8;

extern const double g_BismarckWeightLow_00654900;

extern const float g_DefenderMinisterWeight_00654908;

extern const double g_BullyWeightLow_00654910;

extern const double g_BullyWeightHigh_00654918;

extern const float g_UnreferencedConstant_006545d4;

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp — debug tag literal passed to
// TSimMgr::RebuildMapContextAndGlobalMapState.
extern const char s_Chunk_00698C0C[];

extern "C" char g_bMultiplayerScenarioSetupActive;

extern "C" const char s_PictWvGobPathFormat_00698BF4[];

// TZone.cpp — zone-graph BFS distance cache.
extern int g_nMapActionContextCount;

extern void* g_pMapActionContextDistanceCache;

extern int g_nMapActionContextDistanceCacheSizedFor;

// TGameSetupPicture.cpp — main-menu 'rand' button developer cheat gate: holding shift
// while clicking only takes the instant-random-map shortcut when this flag is set
// (never toggled anywhere in the reachable game code -- likely a build-time/debug-only
// switch in the retail binary). 0x6a42dc.
extern unsigned char g_bRandomMapDeveloperCheatFlag;

extern "C" MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32];

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

} // extern "C"
