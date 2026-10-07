#pragma once
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

// Map-context flavor-text string pool.
extern char s_szSpaceSeparator[];
extern char s_szGaugeCountSeparator[];
extern "C" char s_szRankDotSeparator
    []; // ". " between high-score rank and name (defined in the extern "C" table block)
extern char s_szTurnSummaryIndent[]; // "      " @ 0x696790

extern char s_szTurnHistorySeparator[];

extern char s_szAdmiralPrefix[];

extern char s_szColonSeparator[];

extern char g_szLiteralWb[];

extern char g_szLowercaseX[];

extern "C" {
// Secret garrison-close names used by the retail easter-egg path.
extern const char g_szGarrisonSecretNationNameFrog[];

extern const char g_szGarrisonSecretUnitNameSnidely[];

extern const char* g_pszEmptyTextRef;

extern const char s_DataDirectoryPath[];

extern const char s_IrgGlobPattern[];

extern const char s_NoLanguageFilesMessage[];

extern const char s_OutOfMemoryText[];

extern const char s_ErrorCaption[];

extern int g_lastEdgeAutoScrollTick16;

extern char g_szLiteralL[];

extern char g_szCmdSwitchLangQuit[];

extern _PNH g_pfnPreviousNewHandler;

extern void* g_pAmbitDeveloperAssertProbe;

extern char g_szListSeparator[];

extern char g_szPlusPrefix[];

extern char g_szListConjunction[];

extern LPCSTR g_apFontFiles[];

extern char g_szCountryNameProfileKey[];

extern "C" const double g_TradePowerIdentity;

extern "C" const short g_aTradeItemBasePriceByCategory[0x11];

extern "C" short g_infoPanelLabelXByRow[4];

extern "C" short g_infoPanelLabelYByRow[4];

extern "C" COLORREF g_defaultDropShadowTextColor;

extern char g_szEmptyString[];

extern int g_adwEngineerRailBuildCostByTerrainType[kStrategicTerrainCount];

// TControlSeaZoneMission.cpp / TDefendProvinceMission.cpp / TNavyMission.cpp —
extern const float g_UnreferencedConstant;

extern "C" bool g_bMultiplayerScenarioSetupActive;

extern "C" const char s_PictWvGobPathFormat[];

extern bool g_bRandomMapDeveloperCheatFlag;

extern "C" MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable[23];

} // extern "C"
