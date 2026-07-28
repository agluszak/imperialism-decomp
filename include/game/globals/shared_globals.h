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
// Secret garrison-close names used by the retail easter-egg path.
extern const char g_szGarrisonSecretNationNameFrog[];

extern const char g_szGarrisonSecretUnitNameSnidely[];

extern TAmbitApplication* g_pAmbitApplication;

extern const char* g_pszEmptyTextRef_00669db8;

extern const char s_DataDirectoryPath_006942A8[];

extern const char s_IrgGlobPattern_006942FC[];

extern const char s_NoLanguageFilesMessage_006942B4[];

extern const char s_OutOfMemoryText_006941F0[];

extern const char s_ErrorCaption_00694204[];

extern TDiplomacyMgr* g_pDiplomacyTurnStateManager;

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

extern char g_szListSeparator_00695760[];

extern char g_szPlusPrefix_00698494[];

extern char g_szListConjunction_00698498[];

extern TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;

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

// Shared empty-string literal (ImperialismApp/TCountry/TIncludeView/
// TLowDiskWarningDialog/TModuleLibraryCacheTableStateB/TSimMgr).
extern char g_szEmptyString[];

extern int g_adwEngineerRailBuildCostByTerrainType[kStrategicTerrainCount];

// TControlSeaZoneMission.cpp / TDefendProvinceMission.cpp / TNavyMission.cpp —
extern const float g_UnreferencedConstant_006545d4;

extern "C" char g_bMultiplayerScenarioSetupActive;

extern "C" const char s_PictWvGobPathFormat_00698BF4[];

// TGameSetupPicture.cpp — main-menu 'rand' button developer cheat gate: holding shift
// while clicking only takes the instant-random-map shortcut when this flag is set
// (never toggled anywhere in the reachable game code -- likely a build-time/debug-only
// switch in the retail binary). 0x6a42dc.
extern unsigned char g_bRandomMapDeveloperCheatFlag;

extern "C" MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32];

} // extern "C"
