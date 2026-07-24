#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"
#include "game/ui_tags_common.h"

extern TInfoBarText* g_pCursorControlPanel;

// USmallViews.cpp shared empty-text pointer. The original stores a pointer to
// g_szEmptyString at 0x00662b90 and constructs transient CString values from it in
// TArmyInfoView and the strategic toolbar text-refresh paths.
extern "C" {
extern char* g_pSmallViewsEmptyText_00662B90;
}

extern TTradeMgr* g_pNationInteractionStateManager;

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

extern TTechMgr* g_pCityOrderCapabilityState;

extern TSoundResourceManager g_soundResourceManager;

// Counts idle/audio-state polls before another random cue selection attempt.
extern short g_randomAudioCuePollCounter; // 0x006a4520

extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];

// Tactical unit facing-offset table (0x006a4780); see global_data_tables.cpp.
extern POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

extern TDisplayMgr* g_pDisplayMgr;

extern int g_nUiAnimatorSurfaceBoundsWidth; // 0x006a2228

extern int g_nUiAnimatorSurfaceBoundsHeight; // 0x006a222c

extern TMacViewMgr* g_pStrategicMapViewSystem;

extern TViewMgr* g_pUiRuntimeContext;

extern TAssetMgr* g_pUiViewManager;

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

// Seed viewport offsets copied into TWorldView::viewportOrigin60.x/Y by the TOceanDialog
// ctor; the only known writer (0x56a3b0) zeroes both.
extern int g_nOceanDialogSeedViewportOffsetX; // 0x6a3ff0

extern int g_nOceanDialogSeedViewportOffsetY; // 0x6a3ff4

// Per-ability unit-order cost profile rows (see TUnitOrder::SetOrderCostProfile). 0x695cd0.
extern short g_aUnitOrderCostProfileByAbilityId[0x1e][7];

// Per-tech research cost in gold, indexed by tech id. 0x66ad58.
extern int g_anTechItemResearchCostByTechId[29];

extern TSoundPlayer* g_pSfxPlaybackSystem;

extern TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry;

extern TApplication* g_pApplicationUiRootController;

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
extern "C" char s_szRankDotSeparator_00698ab4
    []; // ". " between high-score rank and name (defined in the extern "C" table block)
extern char s_szTurnSummaryIndent_00696790[]; // "      " @ 0x696790

extern char s_szTurnHistorySeparator_00699320[];

// Enables the clipped vertical offset used by TMiniMapView's viewport marker.
extern unsigned char g_applyMiniMapVerticalClipOffset_006993e8;

extern char s_szAdmiralPrefix_0069578c[];

extern char s_szColonSeparator_00696b10[];

extern char s_mcflavor_00696d10[];

extern char s_mcflavor_006976e0[];

extern char g_szLowercaseX[];

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

extern short g_creditsPlaybackActive_006a4084;

// Zero origin used for the hidden dummy view installed by TInfoBarBehavior.
extern int g_InfoBarDummyOrigin_006A2410[2];

// Need-type indices (into TGreatPower::needCurrentByType/needTargetByType), in priority
// order, that TInteriorMinister::SetCityPolicies (0x4be520) tops up each turn while the
// nation still has need-cap headroom (needCapA6 - needsOverCapFlag).
extern short g_aInteriorMinisterNeedPriorityOrder_00696408[10];

// Naval combat damage-split ratios (TNavyTacUnit::ApplyTacticalDamageAndDeathState, 0x5a63c0):
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

extern TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;

extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;

extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext;

extern TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext;

extern CDib* g_pColorKeyCompositeDib;

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

extern const int g_pTradeSummarySelectionMap[23];

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

extern int g_anWeightedNeighborUnitScoreByType_006955F0[32];

extern short g_anUnitTypeCombatCategoryByType00669858[32];

extern short g_awUnitTypeBaseActionPointTable[32];

extern short g_awTacticalFireSfxTokenByUnitType[32];

extern const char* g_pszEmptyTextRef_00669db8;

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

extern "C" const char g_szBattleSetupTabPathFormat[];

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

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp — debug tag literal passed to
// TSimMgr::RebuildMapContextAndGlobalMapState.
extern const char s_Chunk_00698C0C[];

extern "C" char g_bMultiplayerScenarioSetupActive;

extern "C" const char s_PictWvGobPathFormat_00698BF4[];

// TZone.cpp — zone-graph BFS distance cache (see bd 1uj.16).
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
