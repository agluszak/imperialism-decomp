#pragma once
// Cross-subsystem and unresolved global declarations. Definitions and address markers
// live in src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/core_globals.h"
#include "game/globals/assets_globals.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/globals/ui_text_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/military_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/globals/ui_core_globals.h"
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

extern TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture006A4268;

// Shared substitution value read by TTradeTotalsView::Draw (0x5c1bd0) as
// the sole scanBracketExpressions() argument for its "balance" row template (GetString
// group 0x2740 idx 0x1b). The original's raw bytes are a compile-time-constant pointer
// to an empty string (not a deferred-construction CString), so this is modeled as a
// plain pointer aliasing the shared g_szEmptyString buffer, matching the
// g_pszEmptyTextRef_00669db8 idiom. Not yet pinned to a writer if one exists.
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

extern TSoundResourceManager g_soundResourceManager;

// Counts idle/audio-state polls before another random cue selection attempt.
extern short g_randomAudioCuePollCounter; // 0x006a4520

extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];

// Tactical unit facing-offset table (0x006a4780); see global_data_tables.cpp.
extern POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

extern TLanguageMgr* g_pLanguageMgr;

extern POINT g_ptTechItemModalMessage; // @ 0x6a5820

extern POINT g_ptFormattedErrorModalMessage; // @ 0x6a5ab0

extern POINT g_ptLoungeNationReplacementModalMessage; // @ 0x6a3d98

extern POINT g_ptQueryFloaterModalMessage; // @ 0x6a4048

extern POINT g_ptGameSetupModalMessage; // @ 0x6a4218

extern int g_lastClickedMapTileIndex_006a4608;

extern int g_localizationAudioSlotCursor_006a60f8;

extern char* g_pszDescriptorDefaultName_00653300;

extern char g_szUiCloseParen_006973C8[];

extern POINT g_ptCivilianOrderModalMessage; // @ 0x6a2d40

// Per-ability unit-order cost profile rows (see TUnitOrder::SetOrderCostProfile). 0x695cd0.
extern short g_aUnitOrderCostProfileByAbilityId[0x1e][7];

// Per-tech research cost in gold, indexed by tech id. 0x66ad58.
extern int g_anTechItemResearchCostByTechId[29];

extern TSoundPlayer* g_pSfxPlaybackSystem;

extern TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry;

extern TApplication* g_pApplication;

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

extern "C" {
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

// Left/top of the view-frame clip bounds used by TTacticalBattleView. Reset together by
// ResetUiFrameClipOrigin (0x005ad9e0). 0x6a5458/0x6a545c
extern int g_nUiFrameClipOriginX;

extern int g_nUiFrameClipOriginY;

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

extern TAmbitApplication* g_pAmbitApplication;

extern const char* g_pszEmptyTextRef_00669db8;

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

// Per-nation ordinal used while assigning province names from string-resource groups
// 8000 + nationSlot. GenerateProvinceNames resets all 23 entries before each pass.
extern "C" short g_anProvinceNameOrdinalByNationSlot_006a5af0[23];

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

extern "C" char g_bMultiplayerScenarioSetupActive;

extern "C" const char s_PictWvGobPathFormat_00698BF4[];

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
