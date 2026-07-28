#pragma once
// Cross-subsystem and unresolved global declarations. Definitions and address markers
// live in src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/core_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/globals/assets_globals.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/globals/ui_text_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/military_globals.h"
#include "game/globals/military_ui_globals.h"
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

// Map-context flavor-text string pool (see global_data_tables.cpp).
extern char s_szSpaceSeparator_00695794[];
extern char s_szGaugeCountSeparator_0069936C[];
extern "C" char s_szRankDotSeparator_00698ab4
    []; // ". " between high-score rank and name (defined in the extern "C" table block)
extern char s_szTurnSummaryIndent_00696790[]; // "      " @ 0x696790

extern char s_szTurnHistorySeparator_00699320[];

extern char s_szAdmiralPrefix_0069578c[];

extern char s_szColonSeparator_00696b10[];

extern char g_szLiteralWb_006976E0[];

extern char g_szLowercaseX[];

extern "C" {
// Secret garrison-close names used by the retail easter-egg path.
extern const char g_szGarrisonSecretNationNameFrog[];

extern const char g_szGarrisonSecretUnitNameSnidely[];

extern const char* g_pszEmptyTextRef_00669db8;

extern const char s_DataDirectoryPath_006942A8[];

extern const char s_IrgGlobPattern_006942FC[];

extern const char s_NoLanguageFilesMessage_006942B4[];

extern const char s_OutOfMemoryText_006941F0[];

extern const char s_ErrorCaption_00694204[];

extern int g_lastEdgeAutoScrollTick16;

extern char g_szLiteralL_00694250[];

extern char g_szCmdSwitchLangQuit_00694254[];

extern _PNH g_pfnPreviousNewHandler;

// Read only by ImperialismApp's developer assert command; no writer exists in the retail
// image, so the command deliberately exercises the nil-pointer assert path.
extern void* g_pAmbitDeveloperAssertProbe_006A1358;

extern char g_szListSeparator_00695760[];

extern char g_szPlusPrefix_00698494[];

extern char g_szListConjunction_00698498[];

extern LPCSTR g_apFontFiles[];

extern char g_szCountryNameProfileKey00698AE0[];

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
