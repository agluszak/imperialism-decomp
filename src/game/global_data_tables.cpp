// Real definitions for read-only global data referenced by hand-written code.
//
// These exist so reccmp can pair instruction operands that reference named global
// data (float coefficient tables, named global pointers) instead of bare immediate
// addresses. reccmp maps the original symbol (config/symbols.csv) to the recomp PDB
// symbol by name (the C-linkage leading underscore is stripped), so the *values* here
// are irrelevant to matching — only the symbol identity and its use site matter.
//
// Symbol names below are taken verbatim from config/symbols.csv (including the few
// historically double-named float tables) so the address mapping resolves.

class TControl;
class TView;
class TCursorControlPanel;

#include "game/mfc.h"
#include "game/global_data_tables.h"
#include "game/sea_geometry.h"
#include "game/app_init_globals.h"
#include "game/UiRuntimeContext.h"
#include "game/startup_helpers.h"
#include "game/TNetMgr.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TNavyMgr.h"
#include "game/TSimMgr.h"
#include "game/TAssetMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TLanguageMgr.h"
#include "game/THelpMgr.h"
#include "game/TControl.h"
#include "game/TCursorControlPanel.h"
#include "game/TAnimator.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TBackdropWindow.h"

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// GLOBAL: IMPERIALISM 0x006a4310
TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount] = {0};
// GLOBAL: IMPERIALISM 0x006a2158
TDisplayMgr* g_pDisplayMgr = 0;
// GLOBAL: IMPERIALISM 0x006a21a8
TMacViewMgr* g_pStrategicMapViewSystem = 0;
// GLOBAL: IMPERIALISM 0x006a21bc
TViewMgr* g_pUiRuntimeContext = 0;
// GLOBAL: IMPERIALISM 0x006a2050
TBackdropWindow* DAT_006a2050 = 0;
// GLOBAL: IMPERIALISM 0x006a2054
void* DAT_006a2054 = 0;
// GLOBAL: IMPERIALISM 0x006a2148
TAssetMgr* g_pUiViewManager = 0;
// GLOBAL: IMPERIALISM 0x006a327c
TLanguageMgr* g_pLanguageMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e0
TAnimator* g_pUiAnimator = 0;

extern "C" {

// Diplomacy globals
// GLOBAL: IMPERIALISM 0x006a4280
TMinor* g_apSecondaryNationStateSlots[36] = {0};
// GLOBAL: IMPERIALISM 0x006a432c
// Minor-nation capability object table, iterated as a pointer array. The slot-0x32 loop
// scans entries [0..15] inclusive (`cmp edx, 0x6a4368` == &table[15]); sizing the array to
// 16 lets MSVC emit the sentinel as `g_apMinorNationCapabilityObjects + 0x3c`.
TMinor* g_apMinorNationCapabilityObjects[16] = {0};
// GLOBAL: IMPERIALISM 0x006a429c
// Scanned with g_apMinorNationCapabilityObjects[16].
TMinor* g_apNationAuxRuntimeStateSlots[16] = {0};
// GLOBAL: IMPERIALISM 0x006a4370
TGreatPower* g_apNationStates[7] = {0};
// GLOBAL: IMPERIALISM 0x006a438c
void* g_apNationStates_End;
// GLOBAL: IMPERIALISM 0x006a20f8
TSimMgr* g_pSimMgr = 0;
// GLOBAL: IMPERIALISM 0x006a21b8
THelpMgr* g_pHelpMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e8
TInterNationEventQueueManager* g_pInterNationEventQueueManager = 0;
// GLOBAL: IMPERIALISM 0x006a1344
TApplication* g_pGlobalUiRootController = 0;
// GLOBAL: IMPERIALISM 0x006a43c8
TMultiplayerMgr* g_pGameFlowState = 0;
// GLOBAL: IMPERIALISM 0x006a43d0
TDiplomacyMgr* g_pDiplomacyTurnStateManager = 0;
// GLOBAL: IMPERIALISM 0x006a43e4
TNavyMgr* g_pNavyOrderManager = 0;
// GLOBAL: IMPERIALISM 0x006a3338
TArmyMgr* g_pMapContextActionManager = 0;
char g_vtblTSortedByRelationshipList = 0;
// Last cursor edge-auto-scroll timestamp in GetTickCountDiv16 units
// (TAmbitApplication::HandleCursor, 0x49e320).
// GLOBAL: IMPERIALISM 0x006a21c0
int g_lastEdgeAutoScrollTick16 = 0;
// GLOBAL: IMPERIALISM 0x00695278
int g_nSaveFormatVersion = -1;
// Upper-cased command-line switch literals matched by
// ImperialismCommandLineInfo::ParseParam (0x4133d0).
// GLOBAL: IMPERIALISM 0x00694250
char g_szCmdSwitchLang_00694250[] = "L";
// GLOBAL: IMPERIALISM 0x00694254
char g_szCmdSwitchLangQuit_00694254[] = "L!";
// The MFC application singleton (&theApp), cached by InitInstance (0x412dc0).
// GLOBAL: IMPERIALISM 0x006a1348
class ImperialismApp* g_pImperialismApp = 0;
// GLOBAL: IMPERIALISM 0x006a1350
int DAT_006a1350 = 0;
// Previous CRT new-handler returned by _set_new_handler at startup (write-only).
// GLOBAL: IMPERIALISM 0x006a1354
_PNH g_pfnPreviousNewHandler = 0;

// McAppUI.cpp module globals referenced by TView/TControl widget code. See
// include/game/global_data_tables.h.
// GLOBAL: IMPERIALISM 0x006950ac
int g_McAppUiActiveFlag_006950AC = 1;
// GLOBAL: IMPERIALISM 0x006a1af8
int g_McAppUiDrawGate_006A1AF8 = 0;
// GLOBAL: IMPERIALISM 0x006a1ae0
int g_McAppUiFlag_006A1AE0 = 0;
// GLOBAL: IMPERIALISM 0x006a1ae4
int g_McAppUiFlag_006A1AE4 = 0;
// GLOBAL: IMPERIALISM 0x006a1afc
int g_McAppUiFlag_006A1AFC = 0;
// GLOBAL: IMPERIALISM 0x006a1b00
int g_McAppUiFlag_006A1B00 = 0;
// GLOBAL: IMPERIALISM 0x006a1af0
int g_McAppUiUpdateWindowRecursionGuard_006A1AF0 = 0;
// GLOBAL: IMPERIALISM 0x006a1af4
TView* g_McAppUiActiveRenderContext_006A1AF4 = 0;
// GLOBAL: IMPERIALISM 0x006a1a60
int g_McAppUiDefaultPosX_006A1A60 = 0;
// GLOBAL: IMPERIALISM 0x006a1a64
int g_McAppUiDefaultPosY_006A1A64 = 0;
// GLOBAL: IMPERIALISM 0x006a1a68
TMouseCaptureState g_McAppMouseCaptureState;
// GLOBAL: IMPERIALISM 0x006a1adc
unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC = 0;
// GLOBAL: IMPERIALISM 0x006950b0
char g_szMcAppUiSourcePath_006950B0[] = "D:\\Ambit\\McAppUI.cpp";
// Placeholder strings baked into the turn-event dialog builders (season/treasury/info
// text shown until real values are bound).
// GLOBAL: IMPERIALISM 0x00694354
char g_szUiPlaceholderStaticText_00694354[] = "Static Text";
// GLOBAL: IMPERIALISM 0x00694378
char g_szUiPlaceholderZero_00694378[] = "0";
// GLOBAL: IMPERIALISM 0x006943b0
char g_szUiPlaceholderTreasury_006943B0[] = "$55,555";
// Font face names for the cached-UI-font LOGFONT factory (0x494130); families 2 and 3
// share "Book Antiqua".
// GLOBAL: IMPERIALISM 0x00695160
char g_szQuickDrawFontFaceSystem[] = "System";
// GLOBAL: IMPERIALISM 0x00695140
char g_szQuickDrawFontFaceBookAntiqua[] = "Book Antiqua";
// GLOBAL: IMPERIALISM 0x00695130
char g_szQuickDrawFontFaceSmallFonts[] = "Small Fonts";
// GLOBAL: IMPERIALISM 0x00695108
const char* const g_apszQuickDrawFontFaceNames[5] = {
    g_szQuickDrawFontFaceSystem, g_szUiFontLiteralBelweBdBt, g_szQuickDrawFontFaceBookAntiqua,
    g_szQuickDrawFontFaceBookAntiqua, g_szQuickDrawFontFaceSmallFonts};

// GLOBAL: IMPERIALISM 0x006943bc
char g_szUiPlaceholderSeason_006943BC[] = "Winter, 1888";
// GLOBAL: IMPERIALISM 0x00694a98
char g_szUiPlaceholderSampleText_00694A98[] = "Sample Text 1\n2\n3\n4\n5\n6\n7\n8";
// New-game setup screen (turn event 0x5dd) placeholder label strings, bound by the
// screen builder (group 0x514) until real localized strings replace them.
// GLOBAL: IMPERIALISM 0x006949e0
char g_szNewGameAllAutoGPs_006949E0[] = "All AutoGP's";
// GLOBAL: IMPERIALISM 0x006949f0
char g_szNewGameNamesRandom_006949F0[] = "Random";
// GLOBAL: IMPERIALISM 0x006949f8
char g_szNewGameNamesHistorical_006949F8[] = "Historical";
// GLOBAL: IMPERIALISM 0x00694a08
char g_szNewGameNamesLabel_00694A08[] = "Names:";
// GLOBAL: IMPERIALISM 0x00694a10
char g_szNewGameDifficultySetting_00694A10[] = "Difficulty Setting";
// GLOBAL: IMPERIALISM 0x00694a28
char g_szNewGameDifficultyNighOnImpossible_00694A28[] = "Nigh-On Impossible";
// GLOBAL: IMPERIALISM 0x00694a40
char g_szNewGameDifficultyHard_00694A40[] = "Hard";
// GLOBAL: IMPERIALISM 0x00694a48
char g_szNewGameDifficultyNormal_00694A48[] = "Normal";
// GLOBAL: IMPERIALISM 0x00694a50
char g_szNewGameDifficultyEasy_00694A50[] = "Easy";
// GLOBAL: IMPERIALISM 0x00694a58
char g_szNewGameDifficultyIntroductory_00694A58[] = "Introductory";
// GLOBAL: IMPERIALISM 0x00694a68
char g_szNewGameScenarioPlaceholderTitle_00694A68[] = "Revenge of the Patagonians";
// GLOBAL: IMPERIALISM 0x00694a88
char g_szNewGameGameNameLabel_00694A88[] = "Game name:";
// Trade-board screen labels (InitializeTradeScreenBitmapControls, events 0x7d9/0x7da).
// GLOBAL: IMPERIALISM 0x006948a4
char g_szUiOrdersLabel_006948A4[] = "Orders";
// GLOBAL: IMPERIALISM 0x00694abc
char g_szUiPlaceholder185_00694ABC[] = "185";
// GLOBAL: IMPERIALISM 0x00694ac0
char g_szUiQuantityToOfferLabel_00694AC0[] = "Quantity to Offer";
// GLOBAL: IMPERIALISM 0x00694ad8
char g_szUiAvailableLabel_00694AD8[] = "Available";
// GLOBAL: IMPERIALISM 0x00694ae4
char g_szUiPriceLabel_00694AE4[] = "Price";
// GLOBAL: IMPERIALISM 0x00694aec
char g_szUiCommodityLabel_00694AEC[] = "Commodity";
// GLOBAL: IMPERIALISM 0x00694af8
char g_szUiBoardOfTradeLabel_00694AF8[] = "Board of Trade";

// Placeholder strings baked into the army/navy report screen builders
// (InitializeArmyNavyReportViewsAndCommandTags, events 0x546..0x2506).
// GLOBAL: IMPERIALISM 0x00694540
char g_szUiAsEstimatedBy_00694540[] = "as estimated by";
// GLOBAL: IMPERIALISM 0x00694554
char g_szUiForeignShippingObserved_00694554[] = "Foreign Shipping Observed";
// GLOBAL: IMPERIALISM 0x00694574
char g_szUiHalfDozenShips_00694574[] = "\xa5 Half a dozen Ships-of-the-Line\n2\n3\n4";
// GLOBAL: IMPERIALISM 0x006945a4
char g_szUiNavalForcesReportOf_006945A4[] = "Report of the naval forces of";
// GLOBAL: IMPERIALISM 0x006945c8
char g_szUiPlaceholderPont_006945C8[] = "Pont";
// GLOBAL: IMPERIALISM 0x006945d0
char g_szUiForeignFleetReport_006945D0[] = "Foreign Fleet Report";
// GLOBAL: IMPERIALISM 0x006945ec
char g_szUiTraderIndiamen_006945EC[] = "1 trader, 6 indiamen";
// GLOBAL: IMPERIALISM 0x00694608
char g_szUiStoppedFromTrade_00694608[] = "were stopped from completing their trade";
// GLOBAL: IMPERIALISM 0x0069463c
char g_szUiPlaceholderPokei_0069463C[] = "Pokei";
// GLOBAL: IMPERIALISM 0x00694644
char g_szUiToLabel_00694644[] = "to";
// GLOBAL: IMPERIALISM 0x00694648
char g_szUiItemLabel_00694648[] = "item";
// GLOBAL: IMPERIALISM 0x00694650
char g_szUiCarryingCargoOf_00694650[] = "carrying a cargo of";
// GLOBAL: IMPERIALISM 0x00694668
char g_szUiOwnrTag_00694668[] = "ownr";
// GLOBAL: IMPERIALISM 0x00694670
char g_szUiMerchantsBelongingTo_00694670[] = "Merchants belonging to";
// GLOBAL: IMPERIALISM 0x0069468c
char g_szUiAndConsistingOf_0069468C[] = "and consisting of";
// GLOBAL: IMPERIALISM 0x006946a4
char g_szUiByTaskForceCommandedBy_006946A4[] = "by a task force commanded by";
// GLOBAL: IMPERIALISM 0x006946c8
char g_szUiAdmiralKirk_006946C8[] = " Adm. James T. Kirk of the USS Enterprise";
// GLOBAL: IMPERIALISM 0x006946fc
char g_szUiInThe_006946FC[] = "in the";
// GLOBAL: IMPERIALISM 0x00694704
char g_szUiSeaOfOblongata_00694704[] = "Sea of Oblongata";
// GLOBAL: IMPERIALISM 0x00694718
char g_szUiThreeVessels_00694718[] = "3 vessels";
// GLOBAL: IMPERIALISM 0x00694724
char g_szUiResultOfSuccessful_00694724[] = "A result of a successful";
// GLOBAL: IMPERIALISM 0x00694744
char g_szUiBlockadeLabel_00694744[] = "Blockade";
// GLOBAL: IMPERIALISM 0x00694750
char g_szUiEnemyTradeInterrupted_00694750[] = "Enemy Trade Interrupted";
// GLOBAL: IMPERIALISM 0x0069476c
char g_szUiSeaOfSalamanders_0069476C[] = "Sea of Satanic Salamanders";
// GLOBAL: IMPERIALISM 0x0069478c
char g_szUiEngageAllFloating_0069478C[] = "Engage all floating objects";
// GLOBAL: IMPERIALISM 0x006947b0
char g_szUiForceCurrentlyLocated_006947B0[] = "Force currently located in the";
// GLOBAL: IMPERIALISM 0x006947d8
char g_szUiTaskForceReport_006947D8[] = "Task Force Report";
// GLOBAL: IMPERIALISM 0x006947f0
char g_szUiRegularsLabel_006947F0[] = "Regulars";
// GLOBAL: IMPERIALISM 0x006947fc
char g_szUiSkirmishersLabel_006947FC[] = "Skirmishers";
// GLOBAL: IMPERIALISM 0x0069480c
char g_szUiMinutemanLabel_0069480C[] = "Minuteman";
// GLOBAL: IMPERIALISM 0x00694818
char g_szUiConstructionOptions_00694818[] = "Construction Options";
// GLOBAL: IMPERIALISM 0x00694834
char g_szUiEditTextLabel_00694834[] = "Edit Text";
// GLOBAL: IMPERIALISM 0x00694840
char g_szUiAdmiralBobMinnow_00694840[] = "Adm. Bob of the SS Minnow commanding";
// GLOBAL: IMPERIALISM 0x0069486c
char g_szUiCompositionLabel_0069486C[] = "Composition";
// GLOBAL: IMPERIALISM 0x0069487c
char g_szUiPatrolTheWaters_0069487C[] = "Patrol the waters\nof whereever";
// GLOBAL: IMPERIALISM 0x006948ac
char g_szUiOneHenTwoDucks_006948AC[] = "One hen,\ntwo ducks, \nthree quacking geese.";
// GLOBAL: IMPERIALISM 0x006948e0
char g_szUiArmyReportTitle_006948E0[] = "Army Report";
// GLOBAL: IMPERIALISM 0x006948f0
char g_szUiCivilianReportTitle_006948F0[] = "Civilian Report";
// GLOBAL: IMPERIALISM 0x00694904
char g_szUiLossesHaxaco_00694904[] = "Losses\nHaxaco:  light\nOrdune:  heavy";
// GLOBAL: IMPERIALISM 0x00694930
char g_szUiOrderOfBattle_00694930[] = "Order of Battle follows";
// GLOBAL: IMPERIALISM 0x0069494c
char g_szUiHaxacoLegions_0069494C[] =
    "Haxaco's Powerful Legions\nannhilate\nOrdune's Pathetic Armies";
// GLOBAL: IMPERIALISM 0x00694998
char g_szUiSkirmishReportTitle_00694998[] = "Skirmish Report";
// GLOBAL: IMPERIALISM 0x006949ac
char g_szUiPage14of14_006949AC[] = "Page 14 of 14";

// University-screen (turn event 0x23fa) placeholder label strings.
// GLOBAL: IMPERIALISM 0x006943ac
char g_szUiPlaceholderOne_006943AC[] = "1";
// GLOBAL: IMPERIALISM 0x006949c8
char g_szUiAvailableColon_006949C8[] = "Available:";
// GLOBAL: IMPERIALISM 0x006949d8
char g_szUiCostColon_006949D8[] = "Cost:";
// GLOBAL: IMPERIALISM 0x00694b20
char g_szUiUniversityTitle_00694B20[] = "University";
// GLOBAL: IMPERIALISM 0x00694b30
char g_szUiThousandDollars_00694B30[] = "$1,000";
// GLOBAL: IMPERIALISM 0x00694b38
char g_szUiLevel1_00694B38[] = "Level\n1";
// GLOBAL: IMPERIALISM 0x006943cc
char g_szMcAppUiHeaderPath_006943CC[] = "D:\\Ambit\\McAppUI.h";
// GLOBAL: IMPERIALISM 0x00696bc0
char g_szUGameWindowSourcePath_00696bc0[] = "D:\\Ambit\\Cross\\UGameWindow.cpp";
// TCouncilView::HandleEvent's council-control 4-char tag table ("tfni", "ttrt", "targ",
// "tart", "tuoc", "rffo" as stored).
// GLOBAL: IMPERIALISM 0x00696978
int g_councilControlTagTable[6] = {0x696e6674, 0x74727474, 0x67726174,
                                   0x74726174, 0x636f7574, 0x6f666672};
// GLOBAL: IMPERIALISM 0x006a143c
int g_McAppUiFlag_006A143C = 0;
// GLOBAL: IMPERIALISM 0x006a1b04
int g_McAppUiFlag_006A1B04 = 0;
// GLOBAL: IMPERIALISM 0x006a1b08
int g_McAppUiFlag_006A1B08 = 0;
// GLOBAL: IMPERIALISM 0x006a1b10
int g_McAppUiFlag_006A1B10 = 0;
// GLOBAL: IMPERIALISM 0x006a1b14
int g_McAppUiFlag_006A1B14 = 0;
// GLOBAL: IMPERIALISM 0x006a1b18
int g_McAppUiFlag_006A1B18 = 0;
// GLOBAL: IMPERIALISM 0x006a1b1c
int g_McAppUiFlag_006A1B1C = 0;
// GLOBAL: IMPERIALISM 0x006a1b0c
int g_McAppUiFlag_006A1B0C = 0;

// GLOBAL: IMPERIALISM 0x0064b8f0
int g_Reset_Quick_Draw_Value_0064B8F0 = 1;
// GLOBAL: IMPERIALISM 0x0064b8f4
int g_Reset_Quick_Draw_Value_0064B8F4 = 1;
// GLOBAL: IMPERIALISM 0x0064b8f8
extern const short g_Reset_Quick_Draw_WordState_0064B8F8 = 0;
// GLOBAL: IMPERIALISM 0x006a1d10
short g_Reset_Quick_Draw_State_006A1D10 = 0;
// GLOBAL: IMPERIALISM 0x006a1d08
int g_nQuickDrawStrokeStylePrimary = 0;
// GLOBAL: IMPERIALISM 0x006a1d0c
int g_nQuickDrawStrokeStyleSecondary = 0;
// GLOBAL: IMPERIALISM 0x006a1db4
int g_bQuickDrawStrokePairDirty = 0;
// GLOBAL: IMPERIALISM 0x006a1da8
CRgn* g_pGlobalClipRegionHandleObject = nullptr;
// GLOBAL: IMPERIALISM 0x006950fc
int g_Quick_Draw_Color_State_006950FC = 0x010000FF;
// GLOBAL: IMPERIALISM 0x00695100
int g_uQuickDrawStrokeColor = 0x01000000;
// Cached UI CFont built from the last text-style preset (quickdraw_rendering.cpp,
// 0x494130/0x4944e0). Left zero-initialized to match the original .data image: the
// 0x494460 CRT static-init function seeds mode/flag2/pointSize/styleRef6 to 0xc and
// dirty=1 at runtime; until that init is ported, UpdateGlobalFontPresetAndRebuild
// CachedFontIfDirty still rebuilds on first use via the g_pQuickDrawCachedUiFont==0
// fallback.
// GLOBAL: IMPERIALISM 0x006a1ce8
CFont* g_pQuickDrawCachedUiFont = 0;
// GLOBAL: IMPERIALISM 0x006a1cec
TControlPictureRectState g_QuickDrawCachedFontPreset = {0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a1cf6
unsigned char g_bQuickDrawCachedFontDirty = 0;

// Measure-text cached font cluster. The preset's styleRef6 field (0x6a1d52) IS the
// current text color — written by SetQuickDrawFillColor, read as COLORREF by the paint
// paths (the original PDB labels those 4 bytes g_uQuickDrawCurrentColor; it's the same
// field, not a separate global). The CRT init at 0x4943e0 seeds the preset to 0xc and
// dirty=1 at runtime; left zero-initialized here to match the original .data image, and
// the measure engine rebuilds on first use via the null-cache fallback.
// GLOBAL: IMPERIALISM 0x006a1d48
CFont* g_pQuickDrawCachedMeasureFont = 0;
// GLOBAL: IMPERIALISM 0x006a1d4c
TControlPictureRectState g_QuickDrawMeasureFontPreset = {0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a1d56
unsigned char g_bQuickDrawMeasureFontDirty = 0;
// GLOBAL: IMPERIALISM 0x006a1d80
int g_nQuickDrawOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a1d84
int g_nQuickDrawOriginY = 0;
// Resolved (post-origin-adjustment) text-draw origin, cached by
// SetQuickDrawTextOriginWithContextOffset for the cached-style leaves that consume it.
// GLOBAL: IMPERIALISM 0x006a1d00
int g_nQuickDrawResolvedTextOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a1d04
int g_nQuickDrawResolvedTextOriginY = 0;
// GLOBAL: IMPERIALISM 0x006a1ca0
TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
// Statically initialized to the sentinel address (the dword at 0x006950f8 holds
// 0x006a1ca0 in the original), not null — the restore path in
// BuildStrategicMapCommodityIconAtlasFrom700To722 captures this before the first
// SetActiveQuickDrawSurfaceContext and would otherwise restore a null context.
// GLOBAL: IMPERIALISM 0x006950f8
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead = &g_defaultQuickDrawSurfaceSentinel;
// GLOBAL: IMPERIALISM 0x006a1d60
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a30a8
TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a1da0
CDC* g_pQuickDrawMemoryDc = nullptr;
// GLOBAL: IMPERIALISM 0x006a1dbc
HGDIOBJ g_hQuickDrawSavedBitmap = nullptr;
// GLOBAL: IMPERIALISM 0x006a1db0
int g_nActiveQuickDrawSurfaceFlags = 0;

// Overlay clip cache parameters
// GLOBAL: IMPERIALISM 0x006a4450
int g_nOverlayClipCacheParamX = 0;
// GLOBAL: IMPERIALISM 0x006a4454
int g_nOverlayClipCacheParamY = 0;

// Trade summary selection map — 23 read-only packed-FourCC commodity tags, one
// per TCity commodity slot (Cotton..Gold, i.e. tradeCommodityRecordPtrs[0..0x16]
// / cityStockCottonB6..cityStockGoldE2). Verified via `just ghidra-read-data
// 0x696108 dword 23`: the previous model (a zeroed BSS int[32] at 0x6960e0) had
// the wrong address, wrong size, and wrong storage class — 0x6960e0 actually
// lands inside the unrelated kTradeSellPropagationTags string data below, and
// the real table at 0x696108 is const-initialized, not runtime-populated.
// GLOBAL: IMPERIALISM 0x00696108
const int g_pTradeSummarySelectionMap[23] = {
    0x636f7474, 0x776f6f6c, 0x74696d62, 0x636f616c, 0x69726f6e, 0x686f7273, 0x6f696c20, 0x666f6f64,
    0x66616272, 0x6c756d62, 0x70617065, 0x73746565, 0x6675656c, 0x636c6f74, 0x6675726e, 0x68617264,
    0x61726d61, 0x67726169, 0x70726f64, 0x66697368, 0x6c697665, 0x67656d73, 0x676f6c64,
};

// Trade sell propagation tags
const int kTradeSellPropagationTags[17] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

// Industry action cost weight tables
// GLOBAL: IMPERIALISM 0x00695b50
short g_industryActionCostWeightResCode09[16] = {0, 4, 7, 5, 8, 6, 6, 6, 4, 8, 0, 2, 0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x00695b70
short g_industryActionCostWeightResCode08[16] = {0, 2, 3, 2, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x00695b90
short g_industryActionCostWeightResCode10[16] = {0, 0,  0, 2, 5,  0,  0,  3,
                                                 6, 15, 0, 8, 24, 18, 10, 0};
// GLOBAL: IMPERIALISM 0x00695bb0
short g_industryActionCostWeightResCode0B[16] = {0, 0, 0, 0, 0, 2, 0, 0, 4, 10, 8, 6, 30, 22, 0, 0};
// GLOBAL: IMPERIALISM 0x00695bd0
short g_industryActionCostWeightResCode03[16] = {0,  0,  0,  0,  0, 10, 0, 10,
                                                 10, 20, 20, 20, 0, 0,  0, 0};
// GLOBAL: IMPERIALISM 0x00695bf0
short g_industryActionCostWeightResCode0C[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 20, 0, 0};

// GLOBAL: IMPERIALISM 0x006a1da4
HRGN g_hOpenRgnAccumulator = nullptr;

// GLOBAL: IMPERIALISM 0x006a24d4
char g_Sanitize_City_Counter_Value_006A24D4 = 0;
// GLOBAL: IMPERIALISM 0x6a134c
TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState = nullptr;
// GLOBAL: IMPERIALISM 0x00694150
LPCSTR g_apFontFiles[] = {"data\\WeBeBd__.ttf", "data\\Antqua.ttf", "data\\Antqua.ttf",
                          "data\\AntquaB.ttf", nullptr};
// GLOBAL: IMPERIALISM 0x006a1890
int g_nDibOrientationFlag_006A1890 = 0;
// Probed aux-output (CD-audio line) device index; -1 until
// ProbeAuxOutputDeviceIndexByPidMask (0x5e1430, unported) finds one.
// GLOBAL: IMPERIALISM 0x0069b89c
int g_nAuxOutputDeviceIndex = -1;
// GLOBAL: IMPERIALISM 0x6a1d9c
CDC* g_pScopedMapQuickDrawDcHandleObject = nullptr;
// GLOBAL: IMPERIALISM 0x6a1dac
void* g_pScopedMapQuickDrawViewContext = 0;
// GLOBAL: IMPERIALISM 0x6a1c98
RgnHandle g_pTemporaryRegionCache = 0;

// GLOBAL: IMPERIALISM 0x006a2018
// Cached CCommandLineInfo::m_bShowSplash flag (cmdInfo+0x04 after the CObject vptr).
// Writer: SetCachedShowSplashFlag @ 0x0049cc40 from InitInstance @ 0x00412f81.
// Reader: WrapperFor_AllocateWithFallbackHandler_At0049cc60 @ 0x0049cc60 when nonzero.
BOOL g_cachedShowSplashFlag = FALSE;

} // extern "C"

// Diplomacy helper functions (formerly in diplomacy_globals.cpp).
TGreatPower* GetNationStateBySlot(short slotId) {
  return g_apNationStates[slotId];
}

short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot) {
  return nationState->GetDiplomacyExternalStateByTarget(metricSlot);
}

TGreatPower* GetActiveNationState(void) {
  return g_apNationStates[g_pSimMgr->GetActiveNationId()];
}

int GetTradeSummarySelectionTagByIndex(short index) {
  return g_pTradeSummarySelectionMap[index];
}

// Active root of the in-progress UI resource tree and the entry currently being registered.
// GLOBAL: IMPERIALISM 0x006a141c
TView* g_pUiResourceHead = nullptr;
// GLOBAL: IMPERIALISM 0x006a1420
TView* g_pUiResourceContext = nullptr;

// FUNCTION: IMPERIALISM 0x00489a50
undefined4 SetGlobalUiInvalidationFlagAndReturnPrevious(undefined4 newValue) {
  undefined4 previous = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = newValue;
  return previous;
}

// FUNCTION: IMPERIALISM 0x00489a70
int GetMcAppUiActiveFlag() {
  return g_McAppUiActiveFlag_006950AC;
}

// FUNCTION: IMPERIALISM 0x00489a90
undefined4 ClearGlobalUiInvalidationFlagAndReturnPrevious() {
  undefined4 previous = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = 0;
  return previous;
}

// Source-path string for CMcWindow's McWindow.cpp one-shot debug asserts.
// GLOBAL: IMPERIALISM 0x006950d8
char g_szMcWindowSourcePath_006950D8[] = "D:\\Ambit\\McWindow.cpp";

// Gate read by CMcWindow::OnWindowStateMsg468 before firing the unknown-wParam
// one-shot assert (writer not yet identified).
// GLOBAL: IMPERIALISM 0x006a1c74
int g_nMcWindowStateMsgAssertGate_006A1C74 = 0;

// Source-path string for CIncludeView's IncludeView.cpp one-shot debug asserts.
// GLOBAL: IMPERIALISM 0x00694d10
char g_szIncludeViewSourcePath_00694D10[] = "D:\\Ambit\\IncludeView.cpp";

// Gate read by CIncludeView::OnDialogTreeHostMsg4EF (msg 0x4ef, wParam 0) before firing
// the detach-without-context one-shot assert (writer not yet identified).
// GLOBAL: IMPERIALISM 0x006a17b0
int g_nIncludeViewAssertGate_006A17B0 = 0;

// Gate read by CIncludeView::OnMouseMove (0x4838e4) before firing the
// drag-track-without-context one-shot assert (IncludeView.cpp line 0x2b7).
// GLOBAL: IMPERIALISM 0x006a17c4
int g_nIncludeViewPointerAssertGate_006A17C4 = 0;

extern "C" {
// Default mission score constant (0.0), loaded by the TMission slot 0x68-0x7C float
// stubs (read pointer at 0x0065a468, immediately before the TMission vtable).
// GLOBAL: IMPERIALISM 0x0065a468
extern const float g_MissionDefaultScore_0065a468 = 0.0f;

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. Used by TGreatPower vtable slots 0x88-0x8c.
float g_DAT_Value_00653308[8] = {0};
float g_DAT_Value_00653328[8] = {0};
float g_DAT_Value_00653340[8] = {0};
float g_DAT_Value_00653360[8] = {0};
float g_DAT_Value_00653378[8] = {0};
float g_DAT_Value_00653398[8] = {0};
float g_DAT_006533b0_Value_006533B0[8] = {0};
float g_DAT_006533d0_Value_006533D0[8] = {0};
float g_DAT_006533e8_Value_006533E8[8] = {0};
float g_DAT_Value_00653408[8] = {0};

// Float constants used by the TGreatPower relative-power-score family
// (vtable slots 0x8e-0x9e, bodies 0x004e07b0..0x004e1c20). Values in the
// original image: 0.0f, -0.25f, 0.25f, 0.5f, -90.0f, -0.5f.
extern const float g_Compute_Advisory_Handler_LookupTable_00653700 = 0.0f;
// 0x653704-0x653710 — production-tier classification constants (TGreatPower slot
// 0x82, body 0x004e2880): -1.0, 2.0, 1.0, -2.0.
float g_Classify_Nation_Military_Value_00653704 = -1.0f;
float g_Classify_Nation_Military_Value_00653708 = 2.0f;
float g_Classify_Nation_Military_Value_0065370C = 1.0f;
float g_Classify_Nation_Military_Value_00653710 = -2.0f;
float g_Compute_Advisory_Handler_LookupTable_00653714 = -0.25f;
float g_Iterate_Linked_List_Value_00653718 = 0.25f;
float g_Compute_City_Order_Value_0065371C = 0.5f;
float g_Compute_Advisory_Handler_LookupTable_00653720 = -90.0f;
float g_Compute_Advisory_Peer_LookupTable_00653724 = -0.5f;
float g_ApplyIndexedResourceDeltaScale_00653728 = -1.0f / 255.0f;

// Per-unit-type military stat records (0xe-byte records, 7 shorts each), rebased
// from the earlier 0x695CD4 model: TMilitaryUnit::GetUnitTypeCostPoints (0x5c3400)
// reads the category flag at record offset +0 (0x695cd2; 0x10 = counted) and the
// power/cost points at +2 (0x695cd4, the short the slot 0x8e-0x9c score family sums).
short g_UnitTypeMilitaryStatTable_00695CD2[64][7] = {0};

// Per-unit-type stat table (7 shorts per type; rows for unit types 0x00-0x1d) and
// per-stat divisor baseline used by TMilitaryUnit::GetUnitTypeStatPercent (0x5c3530).
short g_UnitTypeStatTable_0066EB88[30][7] = {0};
short g_UnitTypeStatDivisorTable_0066ED30[7] = {0};

// Per-order-type sort priority (short table at 0x6966d0), used by the TGreatPower
// slot 0x55 tracked-order selection sort (0x004e0290).
short g_DAT_006966d0_Value_006966D0[16] = {0};

// Cursor resource id by civilian-tile-order action code (short table at 0x696678, 12
// entries), used by TCivMgr::LookupCivilianTileOrderCursorTokenByActionIndex (0x4d2930).
short g_civilianTileOrderCursorTokenTable[12] = {0,    1008, 0,    1004, 1003, 1002,
                                                 1018, 1019, 1001, 1003, 1011, 1025};

// Per-unit-type tactical category code (short table at 0x695528); category 0 counts
// as garrison strength in TGreatPower slot 0x11 (0x004d87e0).
short g_awTacticalUnitCategoryCodeBySlot[64] = {0};

// Per-unit-type combat/composition class (short table at 0x695380).
short g_awUnitCombatClassBySlot[64] = {0};
// Stack composition class lookup (byte table at 0x6953c0); indexed [minClass + maxClass*4].
unsigned char g_abStackCompositionClassTable[32] = {0};

// Per-civilian-order-type map-improvement sprite class (short table at 0x697040).
short g_anMapImprovementSpriteClassByOrderType[9] = {2, 3, 1, 6, 0, 7, 5, 4, 8};

// Per-fort-level attacker penalty percent (int table at 0x695568); indexed by
// TGlobalMapCityScoreRecord::fortLevel03.
int g_anFortLevelAttackerPenaltyPercentByLevel[8] = {0};
// Per-unit-type blink/boost eligibility flag (byte table at 0x64c808); indexed by
// TUnit::orderType.
unsigned char g_abUnitTypeBlinkEligibilityFlag[32] = {0};

// Four per-unit-type meter-scoring tables, indexed by TUnit::orderType.
int g_anWeightClassByOrderType[32] = {0};         // int table at 0x64c790
short g_anScaledFactorByOrderType[32] = {0};      // short table at 0x64c660
float g_afPercentEfficiencyByOrderType[32] = {0}; // float table at 0x64c6a0
int g_anCountWeightByOrderType[32] = {0};         // int table at 0x695578

// Per-resourceType requirement table (4 columns per resourceType, 0-23). Read by
// TMapMgr::FindResourceCapabilityRequirementLevel (0x513610).
unsigned char g_abUniversityRequirementLevelById[24][4] = {
    {1, 2, 3, 4}, {1, 2, 3, 4}, {1, 2, 3, 4}, {0, 2, 4, 6}, {0, 2, 4, 6}, {1, 1, 1, 1},
    {0, 2, 4, 6}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0},
    {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {1, 2, 3, 4},
    {1, 2, 3, 4}, {1, 2, 3, 4}, {1, 2, 3, 4}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 0, 0, 0}};
// Per-resourceType "requires tiered nibble" boolean flag table. Read by the same function
// above; only nonzero-ness is consumed there.
unsigned char g_abResourceTypeUsesHighNibbleFlag[24] = {0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Per-resourceType capability-category code. Read by FindMaxResourceCapabilityValueForTile
// (0x513720).
unsigned char g_abResourceTypeCapabilityCategory[24] = {0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Per-resourceType required-order-type code. Read by
// SeedRecruitSearchVisitedStateByCapabilityThresholdAlt (0x515890).
short g_anResourceTypeRequiredOrderType[24] = {2,  5,  3,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                               -1, -1, -1, -1, 2,  2,  6,  5,  -1, -1, 0,  0};
// Per-resourceType "always-qualifies" flag; same caller as above.
unsigned char g_abResourceTypeAlwaysQualifies[24] = {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Per-gateFlag eligibility flag; only indices 0-3 are meaningful (gateFlag's real range).
unsigned char g_abGateFlagQualifies[24] = {
    0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Doubled-column and row hex-direction deltas (direction 0..5), read by
// GetWrappedHexNeighborTileIndexByDirection and BuildHexAreaTileIndexList to step across the
// 0x6c(108)-wide hex grid. Confirmed via raw read of the original .rdata bytes.
short g_Build_Hex_Area_LookupTable_00696E70[6] = {1, 2, 1, -1, -2, -1};
short g_Build_Hex_Area_LookupTable_00696E80[6] = {-1, 0, 1, 1, 0, -1};

unsigned char g_abTerrainTypeSeedGateProfileA[6] = {1, 1, 0, 0, 0, 0};

short g_anTerrainTypeNeighborLinkPriority[8] = {10, 4, 7, 6, 8, 0, 9, 5};

int g_nNextRegionMarkerId = 1;

unsigned char g_bSeedGateNotifyFlag_00696f0a = 0;
unsigned char g_bSeedGateNotifyFlag_00696f0b = 0;
unsigned char g_bSeedGateNotifyFlag_00696f0c = 0;

// Per-tile sprite-variant bitmap-strip offset tables, indexed [gateFlag][spriteVariantIndex01]
// (or, for the 39-suffixed table, by spriteVariantIndex01 alone). Read by
// TMapMgr's rendering-variant lookup family (0x516150/0x5161a0/0x5161e0/0x516220).
short g_awTileSpriteVariantOffsetTable38[4][2] = {
    {0x140, 0x140}, {0, 0}, {0x200, 0x200}, {0x240, 0x240}};
short g_awTileSpriteVariantOffsetTable39[4] = {0x140, 0x980, 0x9c0, 0xa00};
short g_awTileSpriteVariantOffsetTable3a[4][5] = {
    {0x140, 0x140, 0, 0, 0}, {0, 0, 0, 0, 0}, {0x280, 0x280, 0, 0, 0}, {0x340, 0x340, 0, 0, 0}};
short g_awTileSpriteVariantOffsetTable3b[4][2] = {{0, 0}, {0, 0}, {0, 0}, {0, 0}};

// Navy/order composite score table (0x550b60 /
// ComputeNavyOrderPriorityContributionPercentByCategory family); see TNavyOrderResourceDescriptor
// in global_data_tables.h.
TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[64] = {{0}};

// Per-category (0..3) capability metric baseline averages, recomputed at runtime by
// RecomputeGlobalCapabilityAverages (0x54fd50) and read back as the normalization divisor
// by the navy/map-order per-category scoring helpers (0x5501b0, 0x550090, 0x54ff00).
// GLOBAL: IMPERIALISM 0x006a3ec8
int g_aCategoryMetricBaselineAverage[4] = {0};

// Mission score normalization divisor used by the control-sea-zone and blockade-port
// mission scoring helpers.
// GLOBAL: IMPERIALISM 0x0065a9c0
float g_fMissionScoreNormalizationDivisor = 5000.0f;

MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32] = {0};

// Defend-province / mission priority-vector normalization (0x53e6e0 / 0x53ea70 family).
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8 = 0.0f;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0 = 0.0;
double g_Recompute_Nation_Order_LookupTable_0065A9F8 = 0.01;
double g_Recompute_Nation_Order_LookupTable_0065AA00 = 0.5;
double g_Recompute_Nation_Order_LookupTable_0065AA08 = 1.0;
unsigned short g_Recompute_Nation_Order_LookupTable_00697870[0x10] = {0};
unsigned short g_Populate_Beachhead_Mission_LookupTable_00697958[0x10] = {0};

// Army-mission order-priority weight/scoring tables (0x53c620 / 0x53ceb0 /
// 0x53d4a0 family). Sizes are the minimum proven by observed index use;
// g_ArmyMissionCandidateScoreTable_006978f8's row count (state08 range) is
// not yet fully catalogued.
float g_ArmyMissionOrderWeightTable_006978c8[6] = {0};
float g_ArmyMissionDotProductWeights_00697980[5] = {0};
float g_ArmyMissionCandidateScoreTable_006978f8[48] = {0};

// Random-roll scaling constants for TAutoGreatPower::AssignNeedSlotFromSourceSlot19C
// (0x004e7680): 1/255 and 32767.
double g_DAT_00653fc0_Value_00653FC0 = 0.00392156862745098;
double g_DAT_00653fc8_Value_00653FC8 = 32767.0;

// TAutoGreatPower slot 0x9d / 0xa7 scoring constants: -100.0f and 0.5 (double).
float g_Compute_Advisory_Map_Value_00653FD4 = -100.0f;
double g_Evaluate_Advisory_Case11_Value_00653FD8 = 0.5;
extern const float g_Compute_Advisory_Zero_00653FD0 = 0.0f;
double g_Compute_Advisory_MinusSix_00653FE8 = -6.0;
double g_Compute_Advisory_MinusHundred_00653FF0 = -100.0;
double g_Compute_Advisory_Hundred_00654000 = 100.0;
double g_Compute_Advisory_OnePointFive_00654008 = 1.5;

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's city stock block by TGreatPower slot 0x39 (0x004df810).
short g_Rebuild_Primary_Nation_Value_00653570[6][0x17] = {0};

// GLOBAL: IMPERIALISM 0x0066fad0
double DAT_0066fad0 = 0.092;

} // extern "C"

#include "game/TZone.h"
#include "game/TOcean.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TCivMgr.h"
#include "game/TSoundPlayer.h"

// Named global pointers read with a direct absolute load in the original (vs the
// ReadGlobalPointer(imm) shortcut, which emits an extra indirection that cannot pair).
// Defined outside extern "C" so they keep C++ linkage and match typed header declarations.
TZone* g_pMapActionContextListHead = 0;
// GLOBAL: IMPERIALISM 0x006a3fbc
TOcean* g_pActiveMapOrderContext = 0;
TMapMgr* g_pGlobalMapState = 0;
TCivMgr* g_pSelectedCivilianOrderState = 0;
TSoundPlayer* g_pSfxPlaybackSystem = 0;
// GLOBAL: IMPERIALISM 0x006a43cc
TTradeMgr* g_pNationInteractionStateManager = 0;
// GLOBAL: IMPERIALISM 0x006a4220
CString DAT_006a4220;

extern "C" {
short g_awEngineerFortBuildCostByLevel[8] = {0};
int g_adwEngineerRailBuildCostByTerrainType[16] = {0};
// Civilian work-order rescind refund by cost class (nibble from
// GetTileCivilianWorkOrderCostClassNibble); -1 entries are unused classes.
int g_adwCivilianWorkOrderCostByClass[16] = {100, 1000, 5000, -1, -1, -1, 0, 1,
                                             -1,  -1,   2,    3,  4,  -1, 5, 6};

int g_nMapActionContextCount = 0;
void* g_pMapActionContextDistanceCache = 0;
// Count g_pMapActionContextDistanceCache was last sized for (0x006984b4); cache is
// rebuilt whenever g_nMapActionContextCount no longer matches this.
int g_nMapActionContextDistanceCacheSizedFor = 0;

// GLOBAL: IMPERIALISM 0x006a42dc
unsigned char g_bRandomMapDeveloperCheatFlag = 0;
// Developer-cheat probe filename: TSimMgr::InitializeTurnFlowStateDefaults (0x57bc2d)
// stats a file literally named "Conan" via CFile::GetStatus.
// GLOBAL: IMPERIALISM 0x00698bec
char g_szConanCheatFileName_00698BEC[] = "Conan";

// Metric-slot dispatch-order lookup consumed by
// TTradeMgr::ProcessPendingDiplomacyTransferEntriesUntilBlockedWrapper (0x5b9190). Values
// are the original rdata table; kept zero-initialized here (function pairing is by address).
// GLOBAL: IMPERIALISM 0x0066d810
short g_nationMetricSlotDispatchOrder006d810[0x11] = {0};

// GLOBAL: IMPERIALISM 0x006a58c8
int g_defaultDropShadowTextColor = 0;
// GLOBAL: IMPERIALISM 0x006a5fc0
int g_NetworkDefaultNationId006a5fc0 = 0;
// GLOBAL: IMPERIALISM 0x006a5fc4
int g_NetworkBroadcastNationId006a5fc4 = 0;
undefined4 DAT_0066ac88 = 0;
// GLOBAL: IMPERIALISM 0x006a601c
int DAT_006a601c = 0;

// InitInstance asset-path literals (LoadLanguageResourcesFromIrgFiles,
// EnsurePictWvDataGobLoadedBySlot).
// GLOBAL: IMPERIALISM 0x006942a8
extern "C" const char s_DataDirectoryPath_006942A8[] = "Data/";
// GLOBAL: IMPERIALISM 0x006942fc
extern "C" const char s_IrgGlobPattern_006942FC[] = "*.irg";
// GLOBAL: IMPERIALISM 0x006942b4
extern "C" const char s_NoLanguageFilesMessage_006942B4[] =
    "No language files are present. Unable to start Imperialism.";
// Out-of-memory new-handler box (ShowOutOfMemoryErrorNewHandler, 0x412d90).
// GLOBAL: IMPERIALISM 0x006941f0
extern "C" const char s_OutOfMemoryText_006941F0[] = "Out of Memory!!!";
// GLOBAL: IMPERIALISM 0x00694204
extern "C" const char s_ErrorCaption_00694204[] = "Error!!!!!";
// GLOBAL: IMPERIALISM 0x00698bf4
extern "C" const char s_PictWvGobPathFormat_00698BF4[] = "Data/PictWv%d.gob";
// GLOBAL: IMPERIALISM 0x0069b810
extern "C" const char s_MissingFileSuffix_0069B810[] = "' is missing.";
// GLOBAL: IMPERIALISM 0x0069b820
extern "C" const char s_MissingFilePrefix_0069B820[] = "A file required by the program, '";
// GLOBAL: IMPERIALISM 0x00695188
extern "C" const char s_MissingRequiredFileFormat_00695188[] =
    "A file required by the program, '%s,' is missing.";
// GLOBAL: IMPERIALISM 0x006951c4
extern "C" const char s_BmpResourceNameFormat_006951C4[] = "%d.BMP";
// GLOBAL: IMPERIALISM 0x0069b6b4
extern "C" const char s_TurnEventCursorNameFormat_0069B6B4[] = "~C%d";
// GLOBAL: IMPERIALISM 0x0069b6bc
extern "C" const char s_SourcePathUViewMgr_0069B6BC[] = "D:\\Ambit\\Cross\\UViewMgr.cpp";
// GLOBAL: IMPERIALISM 0x00698040
extern "C" const char s_SourcePathUMultiplayerMgr_00698040[] =
    "D:\\Ambit\\Cross\\UMultiplayerMgr.cpp";
// GLOBAL: IMPERIALISM 0x006983c8
extern "C" const char s_SourcePathUNavy_006983C8[] = "D:\\Ambit\\Cross\\UNavy.cpp";
// GLOBAL: IMPERIALISM 0x0069b740
extern "C" const char s_SourcePathUViewMgrMore_0069B740[] = "D:\\Ambit\\Cross\\UViewMgr.more.cpp";
// GLOBAL: IMPERIALISM 0x0069573c
extern "C" const char s_SourcePathUArmyMgr_0069573C[] = "D:\\Ambit\\Cross\\UArmyMgr.cpp";
// GLOBAL: IMPERIALISM 0x0069943c
extern "C" const char s_SourcePathUSuperMap_0069943C[] = "D:\\Ambit\\Cross\\USuperMap.cpp";
// GLOBAL: IMPERIALISM 0x006a460c
short g_defaultMarkerBoxWidth_006a460c = 0;

// Profile string keys used by LoadProfileStringAndAssignSharedRef during multiplayer init.
// GLOBAL: IMPERIALISM 0x00698010
extern "C" const char s_GameName_00698010[] = "GameName";
// GLOBAL: IMPERIALISM 0x0069801c
extern "C" const char s_PlayerName_0069801c[] = "PlayerName";

// InitInstance registry/profile literals (.rdata pointer table @ 0x0063e038).
// GLOBAL: IMPERIALISM 0x006941a8
extern "C" const char s_ProfileLiteralIMPERIALISM_006941A8[] = "IMPERIALISM";
// GLOBAL: IMPERIALISM 0x006941b8
extern "C" const char s_ProfileKeyLanguage_006941B8[] = "Language";
// GLOBAL: IMPERIALISM 0x006941c4
extern "C" const char s_ProfileKeyAutoRes_006941C4[] = "AutoRes";
// GLOBAL: IMPERIALISM 0x006941d0
extern "C" const char s_ProfileSectionSettings_006941D0[] = "Settings";
// GLOBAL: IMPERIALISM 0x006941dc
extern "C" const char s_ProfileAppTitleImperialism_006941DC[] = "Imperialism";
// GLOBAL: IMPERIALISM 0x006941ec
extern "C" const char s_RegistryCompanyNameSSI_006941EC[] = "SSI";
// GLOBAL: IMPERIALISM 0x0063e038
extern "C" const char* const g_pRegistryCompanyKey_0063E038 = s_RegistryCompanyNameSSI_006941EC;
// GLOBAL: IMPERIALISM 0x0063e03c
extern "C" const char* const g_pRegistryAppKey_0063E03C = s_ProfileAppTitleImperialism_006941DC;
// GLOBAL: IMPERIALISM 0x0063e040
extern "C" const char* const g_pRegistrySettingsSection_0063E040 =
    s_ProfileSectionSettings_006941D0;
// GLOBAL: IMPERIALISM 0x0063e044
extern "C" const char* const g_pRegistrySettingsSectionAlt_0063E044 =
    s_ProfileSectionSettings_006941D0;
// GLOBAL: IMPERIALISM 0x0063e048
extern "C" const char* const g_pRegistryAutoResKey_0063E048 = s_ProfileKeyAutoRes_006941C4;
// GLOBAL: IMPERIALISM 0x0063e04c
extern "C" const char* const g_pRegistryLanguageKey_0063E04C = s_ProfileKeyLanguage_006941B8;
// GLOBAL: IMPERIALISM 0x0063e050
extern "C" const char* const g_pRegistryProfileAppName_0063E050 =
    s_ProfileLiteralIMPERIALISM_006941A8;

// Shared empty-string literal at 0x006a13a0 (the "" passed to CString ctors / string
// compares). Defined so reccmp pairs the address reference as a DATA symbol.
#include "decomp_types.h"
char g_szEmptyString[1] = {0};

// GLOBAL: IMPERIALISM 0x006a4490
extern "C" unsigned short g_awCivilianLegendSelectionCountsBySlot[16] = {0};

// GLOBAL: IMPERIALISM 0x698f58
extern "C" short g_anTargetTileProfileByCivilianClassAndSlot[45] = {
    8,  9, -1, -1, -1, 8,  9,  10, 11, 12, 6,  5, 2,  -1, -1, 13, -1, -1, -1, -1, -1, -1, -1,
    -1, 0, 3,  7,  -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, 0,  10, 11, 12, -1, -1};

// Turn-flow cooldown defer counter and side flag (IsTurnCooldownCounterActiveOrResetFlag).
// GLOBAL: IMPERIALISM 0x006a43c4
short g_nTurnCooldownDeferCounter006A43C4 = 0;
// GLOBAL: IMPERIALISM 0x006a43c0 — set once scenario/turn-flow bootstrap completes.
char DAT_006a43c0 = 0;
// GLOBAL: IMPERIALISM 0x006a43f0 — nonzero during multiplayer scenario setup.
char DAT_006a43f0 = 0;
// GLOBAL: IMPERIALISM 0x00698b10
short g_nTurnCooldownSideFlag00698B10 = 1;

// Per-nation scenario setup table copied into TSimMgr's +0xe8 region by the ctor (0x57b9e0)
// and by InitializeTurnFlowStateDefaults. The copy loop reads with a -1 short bias (starts at
// &table[-1]), so the referenced symbol 0x698b1a is one short into the read span. Values
// recovered from the original binary; sized to cover every short the loop reads.
// GLOBAL: IMPERIALISM 0x00698b1a
extern "C" short g_anScenarioNationSetupTable_00698B1A[27] = {
    0x40f,  0x0,  0x41fc, 0x67, 0x410,  0x0,  0x41f4, 0x67, 0x410,  0x0,  0x41e4, 0x67, 0x810, 0x0,
    0x41e0, 0x67, 0x810,  0x0,  0x41d4, 0x67, 0x411,  0x0,  0x41d0, 0x67, 0x411,  0x0,  0x41cc};

// Debug/trace tag literal passed to TSimMgr::RebuildMapContextAndGlobalMapState
// (0x0057c7c0) from case 3 of AdvanceGlobalTurnStateMachine.
// GLOBAL: IMPERIALISM 0x00698c0c
extern "C" const char s_Chunk_00698C0C[] = "Chunk";

// UI default text-style/command-param block copied into every TControl (the 10-byte
// dual-view region at offsets 0x78-0x81); same TControlPictureRectState shape the
// widgets carry. Named so reccmp pairs the direct absolute loads in the TControl ctor.
TControlPictureRectState g_UiResourceEntryDefaultTextStyle = {0, 0, 0, 0};

} // extern "C"

#include "game/TWNetSessionManager.h"

// UGameWindow/dialog-factory widget build stack. The list element type is TView*: its
// vtable family uses the CList<TView*,TView*> serializer/destructors, not the WNet
// CList<void*,void*> copies below.
// GLOBAL: IMPERIALISM 0x006a13e0
CList<TView*, TView*> g_UiWidgetBuildStack006a13e0;

// WNetMgr.cpp file-scope template statics; g_WNetPendingPacketList006a5f40 is the
// local-player pending-packet queue that TNetMgr::Send appends heap packet copies to
// (block size 10, per the original static-init at 0x5e26d0).
// GLOBAL: IMPERIALISM 0x006a5f10
CArray<void*, void*> g_WNetSerializedPtrArrayA006a5f10;
// GLOBAL: IMPERIALISM 0x006a5f28
CArray<void*, void*> g_WNetSerializedPtrArrayB006a5f28;
// GLOBAL: IMPERIALISM 0x006a5f40
CList<void*, void*> g_WNetPendingPacketList006a5f40(10);

// Compiler-emitted dtor copies for the g_UiWidgetBuildStack006a13e0
// CList<TView*,TView*> template instantiation. These previously carried invented
// vtable-address-suffixed placeholder class names.
// TEMPLATE: IMPERIALISM 0x00415f90
// ??_G?$CList@PAVTView@@PAV1@@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x00415e70
// ??1?$CList@PAVTView@@PAV1@@@UAE@XZ

// Compiler-emitted ctor/dtor for the CList<void*,void*> / CArray<void*,void*> template
// instantiations shared by g_WNetPendingPacketList006a5f40 and
// g_WNetSerializedPtrArrayA/B006a5f10/28 above (WNetMgr.cpp TU). bd 1uj.44 (junk-named
// non-RTTI state classes): these previously carried invented vtable-address-suffixed
// placeholder class names (TRuntimeLinkedBlockChainState_0066FA50 /
// TRuntimeHeapBufferOwnerState_0066FA68).
// TEMPLATE: IMPERIALISM 0x005e4540
// ??0?$CList@PAXPAX@@QAE@H@Z

// TEMPLATE: IMPERIALISM 0x005e4580
// ??1?$CList@PAXPAX@@UAE@XZ

// TEMPLATE: IMPERIALISM 0x005e4610
// ?Serialize@?$CList@PAXPAX@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x005e4a30
// ??_G?$CList@PAXPAX@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x005e4780
// ??0?$CArray@PAXPAX@@QAE@XZ

// TEMPLATE: IMPERIALISM 0x005e47b0
// ??1?$CArray@PAXPAX@@UAE@XZ

// DirectPlay session manager object embedded at a fixed address (not a pointer).
// GLOBAL: IMPERIALISM 0x006a5f60
TWNetSessionManager g_NetworkSessionManager006a5f60;

// Global TNetMgr (built by new TNetMgr() during multiplayer init, stored here; every
// turn-event emitter dispatches TNetMgr::Send through it).
// GLOBAL: IMPERIALISM 0x006a6014
TNetMgr* g_pNetMgr006a6014 = 0;

#include "game/TApplication.h"

// GLOBAL: IMPERIALISM 0x006a18e0
TApplication* g_pApplicationUiRootController = 0;

// GLOBAL: IMPERIALISM 0x006a44b0
extern "C" void* g_pActiveCityDialogLegendSelectionOwner = 0;

// GLOBAL: IMPERIALISM 0x006a44b4
// 4-byte flag (written as a dword by TStatusButton::HandleEvent); BOOL-style int.
int g_bCityDialogLegendSelectionInitialized = 0;

// GLOBAL: IMPERIALISM 0x006a590c
TCursorControlPanel* g_pCursorControlPanel = nullptr;

// GLOBAL: IMPERIALISM 0x006a1ab0
int g_turnEventDialogAnchorPoint[2] = {0, 0};

// McAppUI-wide modal-window stack (an MFC CPtrList of TWindow*, base 0x006a1ac0).
// TWindow::ExecuteViewModalStateWithPushPopChain pushes the active window on entry and
// pops it on exit, disabling/re-enabling the window beneath it across the modal run.
CPtrList g_ModalViewStack;

// McAppUI live-view registry: every TWindow/TView links itself in on construction and
// unlinks on teardown; the window-manager iterator (CWMgrIterator) sweeps it.
// GLOBAL: IMPERIALISM 0x006a1a40
CPtrList g_LiveViewRegistry;

// GLOBAL: IMPERIALISM 0x006a1b24
TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry = nullptr;

// GLOBAL: IMPERIALISM 0x006a1d18
GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord = {0, 0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a1dc0
GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord = nullptr;

// UDisplayMgr font-name literals and runtime CString slots (InitializeTurnOrderNavigationDialog).
// GLOBAL: IMPERIALISM 0x00695150
extern "C" const char g_szUiFontLiteralBelweBdBt[] = "Belwe Bd BT";
// GLOBAL: IMPERIALISM 0x00696b6c
extern "C" const char g_szUiFontLiteralPalatino[] = "Palatino";
// GLOBAL: IMPERIALISM 0x00696b78
extern "C" const char g_szUiFontLiteralBelweLight[] = "L Belwe Light";

// GLOBAL: IMPERIALISM 0x006a31bc
extern "C" short g_nTurnFlowNationComparisonAdvisoryTick = 0;

// GLOBAL: IMPERIALISM 0x00694fc8
extern "C" const char g_szUiNilPointerMessage[] = "Nil Pointer";
// GLOBAL: IMPERIALISM 0x00694fd8
extern "C" const char g_szUiFailureMessage[] = "Failure";
// GLOBAL: IMPERIALISM 0x0069430c
extern "C" const char g_szDecimalFormat[] = "%d";

// Great-power pressure tuning tables (.rdata, indexed by the 6-level difficulty/
// locale index; last entry is a 0 sentinel). Values dumped from the original.
// GLOBAL: IMPERIALISM 0x00653498
extern "C" const int g_anNationBasePressureByLocale[6] = {1000, 500, 200, 100, 10, 0};
// GLOBAL: IMPERIALISM 0x006534b0
extern "C" const int g_anGreatPowerPressureMinFloorByLocale[6] = {2, 3, 4, 6, 10, 0};
// GLOBAL: IMPERIALISM 0x006534c8
extern "C" const int g_anGreatPowerEscalationSeedByLocale[6] = {8, 10, 12, 15, 19, 0};
// GLOBAL: IMPERIALISM 0x006534e0
extern "C" const int g_anGreatPowerPressureRiseCapByLocale[6] = {20, 35, 50, 75, 100, 0};
// GLOBAL: IMPERIALISM 0x006534f8
extern "C" const int g_anGreatPowerPressureDecayStepByLocale[6] = {2, 2, 1, 1, 1, 0};
// GLOBAL: IMPERIALISM 0x00653510
extern "C" const int g_anGreatPowerPressureRiseStepByLocale[6] = {1, 1, 1, 2, 3, 0};
// GLOBAL: IMPERIALISM 0x00653528
extern "C" const int g_anGreatPowerCompileThresholdByLocale[6] = {5, 5, 5, 5, 5, 0};
// GLOBAL: IMPERIALISM 0x00653540
extern "C" const int g_anGreatPowerPressureHardAlertThresholdByLocale[6] = {6, 6, 6, 6, 6, 0};
// GLOBAL: IMPERIALISM 0x00653558
extern "C" const int g_anNationStartingTreasuryByLocale[6] = {50000, 10000, 10000, 5000, 5000, 0};

// GLOBAL: IMPERIALISM 0x006a2318
CString g_cstrArmyOrderMessageStore;
// GLOBAL: IMPERIALISM 0x006a3180
CString g_cstrNationComparisonMessageStore;
// GLOBAL: IMPERIALISM 0x006a3d08
CString g_cstrNationAwolMessageStore;
// Message-store slot the TViewMgr prompt helpers (0x5de990/0x5deb40) pass to the
// localized-message dispatch.
// GLOBAL: IMPERIALISM 0x006a5be0
CString g_cstrUiPromptMessageStore;

// The live tactical battle: assigned when a battle object is created/loaded, read by
// the turn-event 0x29/0x2a receive dispatchers.
// GLOBAL: IMPERIALISM 0x006a475c
TTacticalBattle* g_pActiveTacticalBattle;

// OR-accumulator for the turn-event-0x2b presence-mask exchange.
// GLOBAL: IMPERIALISM 0x006a3d64
int g_nTurnEvent2BNationMaskAccumulator;

// Per-unit-type combat-category word table (.rdata): 0 infantry-like, 1/2/3 ranged
// classes, 4 support; indexed by TUnit::orderType.
// GLOBAL: IMPERIALISM 0x00669858
short g_anUnitTypeCombatCategoryByType00669858[32] = {
    0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// Per-unit-type base action-point word table (.rdata); TArmyTacUnit::
// GetBaseActionPoints (0x5a6120) returns this value for the unit's type.
// GLOBAL: IMPERIALISM 0x00669898
short g_awUnitTypeBaseActionPointTable[32] = {40, 60,  40, 40, 110, 90, 50, 30, 40, 60,  40,
                                              40, 110, 90, 60, 30,  50, 70, 50, 40, 110, 90,
                                              80, 30,  40, 40, 50,  90, 90, 90, 0,  0};

// Per-unit-type tactical fire sound-effect token table (.rdata); indexed by
// TTacticalUnit::unitTypeC when a unit fires in the tactical battle.
// GLOBAL: IMPERIALISM 0x00669dc0
short g_awTacticalFireSfxTokenByUnitType[32] = {
    0x3a98, 0x3a98, 0x3a98, 0x3a98, 0x3a99, 0x3a99, 0x3a9b, 0x3a9b, 0x3a98, 0x3a98, 0x3a98,
    0x3a98, 0x3a99, 0x3a99, 0x3a9b, 0x3a9b, 0x3aa6, 0x3aa6, 0x3aa6, 0x3a9c, 0x3aa6, 0x3a9a,
    0x3a9b, 0x3a9b, 0x3a9d, 0x3a9d, 0x3a9d, 0x3a98, 0x3a98, 0x3aa6, 0,      0};

// Force-show flag for the tactical battle view (semantics unverified; OR'd with the
// two per-side watch flags at battle setup).
// GLOBAL: IMPERIALISM 0x006a4758
char g_nForceTacticalBattleViewFlag_006A4758;

// Save-game path construction strings.
// GLOBAL: IMPERIALISM 0x00698708
char g_szImpSaveExtension_00698708[] = ".imp";
// GLOBAL: IMPERIALISM 0x00698710
char g_szMultiplayerSavePrefix_00698710[] = "mult";
// GLOBAL: IMPERIALISM 0x00698718
char g_szSingleSlotSavePrefix_00698718[] = "slot";
// GLOBAL: IMPERIALISM 0x00698720
char g_szSaveFileReadBinaryMode_00698720[] = "rb";
// GLOBAL: IMPERIALISM 0x00698724
char g_szSaveDirectoryPrefix_00698724[] = "Save/";
// GLOBAL: IMPERIALISM 0x0069872c
char g_szAutosaveSlotLabel_0069872C[] = "A";
// GLOBAL: IMPERIALISM 0x0069b848
char g_szSavedDocumentMarker_0069B848[] = "__saved";
// GLOBAL: IMPERIALISM 0x0069b854
char g_szLoadedDocumentMarker_0069B854[] = "__loaded";
// Save-path fragment pointers (.rdata): the TLoadSavePicture save flow reads these
// through pointer loads instead of referencing the literals directly.
// GLOBAL: IMPERIALISM 0x0065ddd0
const char* const g_pszSingleSlotSavePrefix_0065DDD0 = g_szSingleSlotSavePrefix_00698718;
// GLOBAL: IMPERIALISM 0x0065ddd4
const char* const g_pszMultiplayerSavePrefix_0065DDD4 = g_szMultiplayerSavePrefix_00698710;
// GLOBAL: IMPERIALISM 0x0065ddd8
const char* const g_pszImpSaveExtension_0065DDD8 = g_szImpSaveExtension_00698708;
// GLOBAL: IMPERIALISM 0x00697cbc
char g_szClientSavePrefix_00697CBC[] = "cli_";
// GLOBAL: IMPERIALISM 0x0065bf5c
const char* const g_pszClientSavePrefix_0065BF5C = g_szClientSavePrefix_00697CBC;
// Scenario display name copied out of string resource (0x2758, 9) when autosaving; the
// save-slot picker (0x56d2a0) and lifecycle hooks read it back. 0x30 bytes.
// GLOBAL: IMPERIALISM 0x006a2178
char g_ScenarioSaveNameBuffer_006A2178[0x30];
// Default text returned for a null nation descriptor (points at g_szEmptyString).
// GLOBAL: IMPERIALISM 0x00653300
char* g_pszDescriptorDefaultName_00653300 = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x006973c8
char g_szUiCloseParen_006973C8[] = ")";
// GLOBAL: IMPERIALISM 0x0069806c
char g_szUiOpenParen_0069806C[] = "(";
// GLOBAL: IMPERIALISM 0x006a2d40
CString g_cstrCivilianOrderMessageStore;
// GLOBAL: IMPERIALISM 0x006a2df0
CString g_cstrGreatPowerPressureMessage;
// GLOBAL: IMPERIALISM 0x006a3060
CString g_cstrUiFontBelweLight;
// GLOBAL: IMPERIALISM 0x006a3080
CString g_cstrUiFontPalatino;
// GLOBAL: IMPERIALISM 0x006a30a4
CString g_cstrUiFontBelweBdBt;

// One-shot invalidation-flag assert gates (UDisplayMgr.cpp lines 471/495).
// GLOBAL: IMPERIALISM 0x006a30ac
int g_nUiInvalidationAssertFlagLine471 = 0;
// GLOBAL: IMPERIALISM 0x006a30b0
int g_nUiInvalidationAssertFlagLine495 = 0;

// --- UMapper coastline/region overlay tables (plain globals; addresses 0x006a3478 /
// 0x006a3900 are untracked scratch tables). The per-tile-edge Seapoint quads are matched
// into region-border SeaSegments that MergeSmallCityRegionsAndCompactIds consumes. ---
SeapointStretch g_seapointQuadTable_006a3478;
SeaSegmentStretch g_regionBorderLinkTable_006a3900;

// Hex-neighbour offset tables (direction 0..5) for the 108-wide offset-coordinate grid.
const int g_hexColOffsetEvenRow_00697450[6] = {0, 1, 0, -1, -1, -1};
const int g_hexRowOffset_00697468[6] = {-1, 0, 1, 1, 0, -1};
const int g_hexColOffsetOddRow_00697480[6] = {1, 1, 1, 0, -1, 0};

// GLOBAL: IMPERIALISM 0x00696e40
const unsigned short g_hexDirectionBitMasks_00696e40[6] = {1, 2, 4, 8, 16, 32};

// GLOBAL: IMPERIALISM 0x00696ea8
const unsigned short g_hexDirectionBitMasksAlt_00696ea8[7] = {1, 2, 4, 8, 16, 32, 0};

// Map-generation PRNG state + region-seed grid dimensions (plain mutable globals at
// 0x006a38e8/ec/f0, runtime-initialized to 0).
unsigned int g_mapGenLcgState_006a38e8 = 0;
int g_regionSeedGridRows_006a38ec = 0;
int g_regionSeedGridCols_006a38f0 = 0;

// One-shot assert-suppression flags for the UMapper overlay passes (0x006a3910/0x006a3914).
int DAT_006a3910 = 0;
int DAT_006a3914 = 0;

// Zone status-code PRNG seed (0x006a5aec) + display-name cache key (0x006984b8);
// see global_data_tables.h. Runtime-initialized.
// GLOBAL: IMPERIALISM 0x006a5aec
unsigned int g_zoneStatusCodePrngSeed_006a5aec = 0;
// GLOBAL: IMPERIALISM 0x006984b8 (static init -1 in the original .data section)
int g_mapActionContextDisplayNameCacheId_006984b8 = -1;
// GLOBAL: IMPERIALISM 0x006984bc (static init 7 in the original .data section)
int g_mapActionContextDisplayNameCacheStep_006984bc = 7;

// === Map-context flavor-text string pool (procedural syllable/grammar .rdata literals
// referenced by the BuildMapContextStatusString / GenerateMappedFlavorText family).
// Empty content: reccmp pairs by the // GLOBAL address marker, not by value. ===
// GLOBAL: IMPERIALISM 0x00695794
char s_mcflavor_00695794[] = "";
// GLOBAL: IMPERIALISM 0x00696674
char s_mcflavor_00696674[] = "";
// GLOBAL: IMPERIALISM 0x00696d10
char s_mcflavor_00696d10[] = "";
// GLOBAL: IMPERIALISM 0x00697238
char s_mcflavor_00697238[] = "";
// GLOBAL: IMPERIALISM 0x006976e0
char s_mcflavor_006976e0[] = "";
// GLOBAL: IMPERIALISM 0x00698b0c
char s_mcflavor_00698b0c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab00
char s_mcflavor_0069ab00[] = "";
// GLOBAL: IMPERIALISM 0x0069ab04
char s_mcflavor_0069ab04[] = "";
// GLOBAL: IMPERIALISM 0x0069ab08
char s_mcflavor_0069ab08[] = "";
// GLOBAL: IMPERIALISM 0x0069ab0c
char s_mcflavor_0069ab0c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab10
char s_mcflavor_0069ab10[] = "";
// GLOBAL: IMPERIALISM 0x0069ab14
char s_mcflavor_0069ab14[] = "";
// GLOBAL: IMPERIALISM 0x0069ab18
char s_mcflavor_0069ab18[] = "";
// GLOBAL: IMPERIALISM 0x0069ab1c
char s_mcflavor_0069ab1c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab20
char s_mcflavor_0069ab20[] = "";
// GLOBAL: IMPERIALISM 0x0069ab24
char s_mcflavor_0069ab24[] = "";
// GLOBAL: IMPERIALISM 0x0069ab28
char s_mcflavor_0069ab28[] = "";
// GLOBAL: IMPERIALISM 0x0069ab2c
char s_mcflavor_0069ab2c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab30
char s_mcflavor_0069ab30[] = "";
// GLOBAL: IMPERIALISM 0x0069ab34
char s_mcflavor_0069ab34[] = "";
// GLOBAL: IMPERIALISM 0x0069ab38
char s_mcflavor_0069ab38[] = "";
// GLOBAL: IMPERIALISM 0x0069ab3c
char s_mcflavor_0069ab3c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab40
char s_mcflavor_0069ab40[] = "";
// GLOBAL: IMPERIALISM 0x0069ab44
char s_mcflavor_0069ab44[] = "";
// GLOBAL: IMPERIALISM 0x0069ab48
char s_mcflavor_0069ab48[] = "";
// GLOBAL: IMPERIALISM 0x0069ab4c
char s_mcflavor_0069ab4c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab50
char s_mcflavor_0069ab50[] = "";
// GLOBAL: IMPERIALISM 0x0069ab54
char s_mcflavor_0069ab54[] = "";
// GLOBAL: IMPERIALISM 0x0069ab58
char s_mcflavor_0069ab58[] = "";
// GLOBAL: IMPERIALISM 0x0069ab5c
char s_mcflavor_0069ab5c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab60
char s_mcflavor_0069ab60[] = "";
// GLOBAL: IMPERIALISM 0x0069ab64
char s_mcflavor_0069ab64[] = "";
// GLOBAL: IMPERIALISM 0x0069ab68
char s_mcflavor_0069ab68[] = "";
// GLOBAL: IMPERIALISM 0x0069ab6c
char s_mcflavor_0069ab6c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab70
char s_mcflavor_0069ab70[] = "";
// GLOBAL: IMPERIALISM 0x0069ab74
char s_mcflavor_0069ab74[] = "";
// GLOBAL: IMPERIALISM 0x0069ab78
char s_mcflavor_0069ab78[] = "";
// GLOBAL: IMPERIALISM 0x0069ab7c
char s_mcflavor_0069ab7c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab80
char s_mcflavor_0069ab80[] = "";
// GLOBAL: IMPERIALISM 0x0069ab84
char s_mcflavor_0069ab84[] = "";
// GLOBAL: IMPERIALISM 0x0069ab88
char s_mcflavor_0069ab88[] = "";
// GLOBAL: IMPERIALISM 0x0069ab8c
char s_mcflavor_0069ab8c[] = "";
// GLOBAL: IMPERIALISM 0x0069ab90
char s_mcflavor_0069ab90[] = "";
// GLOBAL: IMPERIALISM 0x0069ab94
char s_mcflavor_0069ab94[] = "";
// GLOBAL: IMPERIALISM 0x0069ab98
char s_mcflavor_0069ab98[] = "";
// GLOBAL: IMPERIALISM 0x0069ab9c
char s_mcflavor_0069ab9c[] = "";
// GLOBAL: IMPERIALISM 0x0069aba0
char s_mcflavor_0069aba0[] = "";
// GLOBAL: IMPERIALISM 0x0069aba4
char s_mcflavor_0069aba4[] = "";
// GLOBAL: IMPERIALISM 0x0069aba8
char s_mcflavor_0069aba8[] = "";
// GLOBAL: IMPERIALISM 0x0069abac
char s_mcflavor_0069abac[] = "";
// GLOBAL: IMPERIALISM 0x0069abb0
char s_mcflavor_0069abb0[] = "";
// GLOBAL: IMPERIALISM 0x0069abb4
char s_mcflavor_0069abb4[] = "";
// GLOBAL: IMPERIALISM 0x0069abb8
char s_mcflavor_0069abb8[] = "";
// GLOBAL: IMPERIALISM 0x0069abbc
char s_mcflavor_0069abbc[] = "";
// GLOBAL: IMPERIALISM 0x0069abc0
char s_mcflavor_0069abc0[] = "";
// GLOBAL: IMPERIALISM 0x0069abc4
char s_mcflavor_0069abc4[] = "";
// GLOBAL: IMPERIALISM 0x0069abcc
char s_mcflavor_0069abcc[] = "";
// GLOBAL: IMPERIALISM 0x0069abd0
char s_mcflavor_0069abd0[] = "";
// GLOBAL: IMPERIALISM 0x0069abd4
char s_mcflavor_0069abd4[] = "";
// GLOBAL: IMPERIALISM 0x0069abd8
char s_mcflavor_0069abd8[] = "";
// GLOBAL: IMPERIALISM 0x0069abdc
char s_mcflavor_0069abdc[] = "";
// GLOBAL: IMPERIALISM 0x0069abe0
char s_mcflavor_0069abe0[] = "";
// GLOBAL: IMPERIALISM 0x0069abe4
char s_mcflavor_0069abe4[] = "";
// GLOBAL: IMPERIALISM 0x0069abe8
char s_mcflavor_0069abe8[] = "";
// GLOBAL: IMPERIALISM 0x0069abec
char s_mcflavor_0069abec[] = "";
// GLOBAL: IMPERIALISM 0x0069abf0
char s_mcflavor_0069abf0[] = "";
// GLOBAL: IMPERIALISM 0x0069abf4
char s_mcflavor_0069abf4[] = "";
// GLOBAL: IMPERIALISM 0x0069abf8
char s_mcflavor_0069abf8[] = "";
// GLOBAL: IMPERIALISM 0x0069abfc
char s_mcflavor_0069abfc[] = "";
// GLOBAL: IMPERIALISM 0x0069ac00
char s_mcflavor_0069ac00[] = "";
// GLOBAL: IMPERIALISM 0x0069ac04
char s_mcflavor_0069ac04[] = "";
// GLOBAL: IMPERIALISM 0x0069ac08
char s_mcflavor_0069ac08[] = "";
// GLOBAL: IMPERIALISM 0x0069ac0c
char s_mcflavor_0069ac0c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac10
char s_mcflavor_0069ac10[] = "";
// GLOBAL: IMPERIALISM 0x0069ac14
char s_mcflavor_0069ac14[] = "";
// GLOBAL: IMPERIALISM 0x0069ac18
char s_mcflavor_0069ac18[] = "";
// GLOBAL: IMPERIALISM 0x0069ac1c
char s_mcflavor_0069ac1c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac20
char s_mcflavor_0069ac20[] = "";
// GLOBAL: IMPERIALISM 0x0069ac24
char s_mcflavor_0069ac24[] = "";
// GLOBAL: IMPERIALISM 0x0069ac28
char s_mcflavor_0069ac28[] = "";
// GLOBAL: IMPERIALISM 0x0069ac2c
char s_mcflavor_0069ac2c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac30
char s_mcflavor_0069ac30[] = "";
// GLOBAL: IMPERIALISM 0x0069ac38
char s_mcflavor_0069ac38[] = "";
// GLOBAL: IMPERIALISM 0x0069ac3c
char s_mcflavor_0069ac3c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac40
char s_mcflavor_0069ac40[] = "";
// GLOBAL: IMPERIALISM 0x0069ac44
char s_mcflavor_0069ac44[] = "";
// GLOBAL: IMPERIALISM 0x0069ac48
char s_mcflavor_0069ac48[] = "";
// GLOBAL: IMPERIALISM 0x0069ac4c
char s_mcflavor_0069ac4c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac50
char s_mcflavor_0069ac50[] = "";
// GLOBAL: IMPERIALISM 0x0069ac54
char s_mcflavor_0069ac54[] = "";
// GLOBAL: IMPERIALISM 0x0069ac58
char s_mcflavor_0069ac58[] = "";
// GLOBAL: IMPERIALISM 0x0069ac5c
char s_mcflavor_0069ac5c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac60
char s_mcflavor_0069ac60[] = "";
// GLOBAL: IMPERIALISM 0x0069ac6c
char s_mcflavor_0069ac6c[] = "";
// GLOBAL: IMPERIALISM 0x0069ac74
char s_mcflavor_0069ac74[] = "";
// GLOBAL: IMPERIALISM 0x0069ac80
char s_mcflavor_0069ac80[] = "";
// GLOBAL: IMPERIALISM 0x0069ac88
char s_mcflavor_0069ac88[] = "";
// GLOBAL: IMPERIALISM 0x0069ac90
char s_mcflavor_0069ac90[] = "";
// GLOBAL: IMPERIALISM 0x0069ac98
char s_mcflavor_0069ac98[] = "";
// GLOBAL: IMPERIALISM 0x0069ac9c
char s_mcflavor_0069ac9c[] = "";
// GLOBAL: IMPERIALISM 0x0069aca0
char s_mcflavor_0069aca0[] = "";
// GLOBAL: IMPERIALISM 0x0069aca4
char s_mcflavor_0069aca4[] = "";
// GLOBAL: IMPERIALISM 0x0069aca8
char s_mcflavor_0069aca8[] = "";
// GLOBAL: IMPERIALISM 0x0069acac
char s_mcflavor_0069acac[] = "";
// GLOBAL: IMPERIALISM 0x0069acb0
char s_mcflavor_0069acb0[] = "";
// GLOBAL: IMPERIALISM 0x0069acb4
char s_mcflavor_0069acb4[] = "";
// GLOBAL: IMPERIALISM 0x0069acb8
char s_mcflavor_0069acb8[] = "";
// GLOBAL: IMPERIALISM 0x0069acbc
char s_mcflavor_0069acbc[] = "";
// GLOBAL: IMPERIALISM 0x0069acc0
char s_mcflavor_0069acc0[] = "";
// GLOBAL: IMPERIALISM 0x0069acc4
char s_mcflavor_0069acc4[] = "";
// GLOBAL: IMPERIALISM 0x0069acc8
char s_mcflavor_0069acc8[] = "";
// GLOBAL: IMPERIALISM 0x0069accc
char s_mcflavor_0069accc[] = "";
// GLOBAL: IMPERIALISM 0x0069acd0
char s_mcflavor_0069acd0[] = "";
// GLOBAL: IMPERIALISM 0x0069acd4
char s_mcflavor_0069acd4[] = "";
// GLOBAL: IMPERIALISM 0x0069acd8
char s_mcflavor_0069acd8[] = "";
// GLOBAL: IMPERIALISM 0x0069acdc
char s_mcflavor_0069acdc[] = "";
// GLOBAL: IMPERIALISM 0x0069ace0
char s_mcflavor_0069ace0[] = "";
// GLOBAL: IMPERIALISM 0x0069ace4
char s_mcflavor_0069ace4[] = "";
// GLOBAL: IMPERIALISM 0x0069ace8
char s_mcflavor_0069ace8[] = "";
// GLOBAL: IMPERIALISM 0x0069acec
char s_mcflavor_0069acec[] = "";
// GLOBAL: IMPERIALISM 0x0069acf0
char s_mcflavor_0069acf0[] = "";
// GLOBAL: IMPERIALISM 0x0069acf4
char s_mcflavor_0069acf4[] = "";
// GLOBAL: IMPERIALISM 0x0069acf8
char s_mcflavor_0069acf8[] = "";
// GLOBAL: IMPERIALISM 0x0069acfc
char s_mcflavor_0069acfc[] = "";
// GLOBAL: IMPERIALISM 0x0069ad00
char s_mcflavor_0069ad00[] = "";
// GLOBAL: IMPERIALISM 0x0069ad04
char s_mcflavor_0069ad04[] = "";
// GLOBAL: IMPERIALISM 0x0069ad0c
char s_mcflavor_0069ad0c[] = "";
// GLOBAL: IMPERIALISM 0x0069ad14
char s_mcflavor_0069ad14[] = "";
// GLOBAL: IMPERIALISM 0x0069ad20
char s_mcflavor_0069ad20[] = "";
// GLOBAL: IMPERIALISM 0x0069ad24
char s_mcflavor_0069ad24[] = "";
// GLOBAL: IMPERIALISM 0x0069ad28
char s_mcflavor_0069ad28[] = "";
// GLOBAL: IMPERIALISM 0x0069ad2c
char s_mcflavor_0069ad2c[] = "";
// GLOBAL: IMPERIALISM 0x0069ad30
char s_mcflavor_0069ad30[] = "";
// GLOBAL: IMPERIALISM 0x0069ad34
char s_mcflavor_0069ad34[] = "";
// GLOBAL: IMPERIALISM 0x0069ad38
char s_mcflavor_0069ad38[] = "";
// GLOBAL: IMPERIALISM 0x0069ad3c
char s_mcflavor_0069ad3c[] = "";
// GLOBAL: IMPERIALISM 0x0069ad40
char s_mcflavor_0069ad40[] = "";
// GLOBAL: IMPERIALISM 0x0069ad44
char s_mcflavor_0069ad44[] = "";
// GLOBAL: IMPERIALISM 0x0069ad48
char s_mcflavor_0069ad48[] = "";
// GLOBAL: IMPERIALISM 0x0069ad4c
char s_mcflavor_0069ad4c[] = "";
// GLOBAL: IMPERIALISM 0x0069ad50
char s_mcflavor_0069ad50[] = "";
// GLOBAL: IMPERIALISM 0x0069ad54
char s_mcflavor_0069ad54[] = "";
// GLOBAL: IMPERIALISM 0x0069ad58
char s_mcflavor_0069ad58[] = "";
// GLOBAL: IMPERIALISM 0x0069ad60
char s_mcflavor_0069ad60[] = "";
// GLOBAL: IMPERIALISM 0x0069ad68
char s_mcflavor_0069ad68[] = "";
// GLOBAL: IMPERIALISM 0x0069ad70
char s_mcflavor_0069ad70[] = "";
// GLOBAL: IMPERIALISM 0x0069ad78
char s_mcflavor_0069ad78[] = "";
// GLOBAL: IMPERIALISM 0x0069ad84
char s_mcflavor_0069ad84[] = "";
// GLOBAL: IMPERIALISM 0x0069ad8c
char s_mcflavor_0069ad8c[] = "";
// GLOBAL: IMPERIALISM 0x0069ad90
char s_mcflavor_0069ad90[] = "";
// GLOBAL: IMPERIALISM 0x0069ad94
char s_mcflavor_0069ad94[] = "";
// GLOBAL: IMPERIALISM 0x0069ad98
char s_mcflavor_0069ad98[] = "";
// GLOBAL: IMPERIALISM 0x0069ad9c
char s_mcflavor_0069ad9c[] = "";
// GLOBAL: IMPERIALISM 0x0069ada0
char s_mcflavor_0069ada0[] = "";
// GLOBAL: IMPERIALISM 0x0069ada4
char s_mcflavor_0069ada4[] = "";
// GLOBAL: IMPERIALISM 0x0069ada8
char s_mcflavor_0069ada8[] = "";
// GLOBAL: IMPERIALISM 0x0069adac
char s_mcflavor_0069adac[] = "";
// GLOBAL: IMPERIALISM 0x0069adb0
char s_mcflavor_0069adb0[] = "";
// GLOBAL: IMPERIALISM 0x0069adb4
char s_mcflavor_0069adb4[] = "";
// GLOBAL: IMPERIALISM 0x0069adb8
char s_mcflavor_0069adb8[] = "";
// GLOBAL: IMPERIALISM 0x0069adbc
char s_mcflavor_0069adbc[] = "";
// GLOBAL: IMPERIALISM 0x0069adc0
char s_mcflavor_0069adc0[] = "";
// GLOBAL: IMPERIALISM 0x0069adc4
char s_mcflavor_0069adc4[] = "";
// GLOBAL: IMPERIALISM 0x0069adc8
char s_mcflavor_0069adc8[] = "";
// GLOBAL: IMPERIALISM 0x0069adcc
char s_mcflavor_0069adcc[] = "";
// GLOBAL: IMPERIALISM 0x0069add0
char s_mcflavor_0069add0[] = "";
// GLOBAL: IMPERIALISM 0x0069add4
char s_mcflavor_0069add4[] = "";
// GLOBAL: IMPERIALISM 0x0069add8
char s_mcflavor_0069add8[] = "";
// GLOBAL: IMPERIALISM 0x0069addc
char s_mcflavor_0069addc[] = "";
// GLOBAL: IMPERIALISM 0x0069ade0
char s_mcflavor_0069ade0[] = "";
// GLOBAL: IMPERIALISM 0x0069ade4
char s_mcflavor_0069ade4[] = "";
// GLOBAL: IMPERIALISM 0x0069ade8
char s_mcflavor_0069ade8[] = "";
// GLOBAL: IMPERIALISM 0x0069adec
char s_mcflavor_0069adec[] = "";
// GLOBAL: IMPERIALISM 0x0069adf0
char s_mcflavor_0069adf0[] = "";
// GLOBAL: IMPERIALISM 0x0069adf4
char s_mcflavor_0069adf4[] = "";
// GLOBAL: IMPERIALISM 0x0069adf8
char s_mcflavor_0069adf8[] = "";
// GLOBAL: IMPERIALISM 0x0069adfc
char s_mcflavor_0069adfc[] = "";
// GLOBAL: IMPERIALISM 0x0069ae00
char s_mcflavor_0069ae00[] = "";
// GLOBAL: IMPERIALISM 0x0069ae04
char s_mcflavor_0069ae04[] = "";
// GLOBAL: IMPERIALISM 0x0069ae08
char s_mcflavor_0069ae08[] = "";
// GLOBAL: IMPERIALISM 0x0069ae0c
char s_mcflavor_0069ae0c[] = "";
// GLOBAL: IMPERIALISM 0x0069ae10
char s_mcflavor_0069ae10[] = "";
// GLOBAL: IMPERIALISM 0x0069ae14
char s_mcflavor_0069ae14[] = "";
// GLOBAL: IMPERIALISM 0x0069ae18
char s_mcflavor_0069ae18[] = "";
// GLOBAL: IMPERIALISM 0x0069ae24
char s_mcflavor_0069ae24[] = "";
// GLOBAL: IMPERIALISM 0x0069ae30
char s_mcflavor_0069ae30[] = "";
// GLOBAL: IMPERIALISM 0x0069ae34
char s_mcflavor_0069ae34[] = "";
// GLOBAL: IMPERIALISM 0x0069ae38
char s_mcflavor_0069ae38[] = "";
// GLOBAL: IMPERIALISM 0x0069ae3c
char s_mcflavor_0069ae3c[] = "";
// GLOBAL: IMPERIALISM 0x0069ae40
char s_mcflavor_0069ae40[] = "";
// GLOBAL: IMPERIALISM 0x0069ae44
char s_mcflavor_0069ae44[] = "";
// GLOBAL: IMPERIALISM 0x0069ae48
char s_mcflavor_0069ae48[] = "";
// GLOBAL: IMPERIALISM 0x0069ae4c
char s_mcflavor_0069ae4c[] = "";
// GLOBAL: IMPERIALISM 0x0069ae50
char s_mcflavor_0069ae50[] = "";
// GLOBAL: IMPERIALISM 0x0069ae54
char s_mcflavor_0069ae54[] = "";
// GLOBAL: IMPERIALISM 0x0069ae58
char s_mcflavor_0069ae58[] = "";
// GLOBAL: IMPERIALISM 0x0069ae5c
char s_mcflavor_0069ae5c[] = "";
// GLOBAL: IMPERIALISM 0x0069ae60
char s_mcflavor_0069ae60[] = "";
// GLOBAL: IMPERIALISM 0x0069ae64
char s_mcflavor_0069ae64[] = "";
// GLOBAL: IMPERIALISM 0x0069ae68
char s_mcflavor_0069ae68[] = "";
// GLOBAL: IMPERIALISM 0x0069ae6c
char s_mcflavor_0069ae6c[] = "";
// GLOBAL: IMPERIALISM 0x0069ae70
char s_mcflavor_0069ae70[] = "";
// GLOBAL: IMPERIALISM 0x0069ae74
char s_mcflavor_0069ae74[] = "";
// GLOBAL: IMPERIALISM 0x0069ae78
char s_mcflavor_0069ae78[] = "";
// GLOBAL: IMPERIALISM 0x0069ae7c
char s_mcflavor_0069ae7c[] = "";
// GLOBAL: IMPERIALISM 0x0069ae80
char s_mcflavor_0069ae80[] = "";
// GLOBAL: IMPERIALISM 0x0069ae84
char s_mcflavor_0069ae84[] = "";
// GLOBAL: IMPERIALISM 0x0069ae88
char s_mcflavor_0069ae88[] = "";
// GLOBAL: IMPERIALISM 0x0069ae90
char s_mcflavor_0069ae90[] = "";
// GLOBAL: IMPERIALISM 0x0069ae94
char s_mcflavor_0069ae94[] = "";
// GLOBAL: IMPERIALISM 0x0069ae98
char s_mcflavor_0069ae98[] = "";
// GLOBAL: IMPERIALISM 0x0069aea0
char s_mcflavor_0069aea0[] = "";
// GLOBAL: IMPERIALISM 0x0069aea8
char s_mcflavor_0069aea8[] = "";
// GLOBAL: IMPERIALISM 0x0069aeac
char s_mcflavor_0069aeac[] = "";
// GLOBAL: IMPERIALISM 0x0069aeb4
char s_mcflavor_0069aeb4[] = "";
// GLOBAL: IMPERIALISM 0x0069aeb8
char s_mcflavor_0069aeb8[] = "";
// GLOBAL: IMPERIALISM 0x0069aebc
char s_mcflavor_0069aebc[] = "";
// GLOBAL: IMPERIALISM 0x0069aec0
char s_mcflavor_0069aec0[] = "";
// GLOBAL: IMPERIALISM 0x0069aec4
char s_mcflavor_0069aec4[] = "";
// GLOBAL: IMPERIALISM 0x0069aec8
char s_mcflavor_0069aec8[] = "";
// GLOBAL: IMPERIALISM 0x0069aecc
char s_mcflavor_0069aecc[] = "";
// GLOBAL: IMPERIALISM 0x0069aed0
char s_mcflavor_0069aed0[] = "";
// GLOBAL: IMPERIALISM 0x0069aed4
char s_mcflavor_0069aed4[] = "";
// GLOBAL: IMPERIALISM 0x0069aed8
char s_mcflavor_0069aed8[] = "";
// GLOBAL: IMPERIALISM 0x0069aedc
char s_mcflavor_0069aedc[] = "";
// GLOBAL: IMPERIALISM 0x0069aee0
char s_mcflavor_0069aee0[] = "";
// GLOBAL: IMPERIALISM 0x0069aee4
char s_mcflavor_0069aee4[] = "";
// GLOBAL: IMPERIALISM 0x0069aeec
char s_mcflavor_0069aeec[] = "";
// GLOBAL: IMPERIALISM 0x0069aef8
char s_mcflavor_0069aef8[] = "";
// GLOBAL: IMPERIALISM 0x0069af00
char s_mcflavor_0069af00[] = "";
// GLOBAL: IMPERIALISM 0x0069af08
char s_mcflavor_0069af08[] = "";
// GLOBAL: IMPERIALISM 0x0069af0c
char s_mcflavor_0069af0c[] = "";
// GLOBAL: IMPERIALISM 0x0069af18
char s_mcflavor_0069af18[] = "";
// GLOBAL: IMPERIALISM 0x0069af1c
char s_mcflavor_0069af1c[] = "";
// GLOBAL: IMPERIALISM 0x0069af20
char s_mcflavor_0069af20[] = "";
// GLOBAL: IMPERIALISM 0x0069af24
char s_mcflavor_0069af24[] = "";
// GLOBAL: IMPERIALISM 0x0069af28
char s_mcflavor_0069af28[] = "";
// GLOBAL: IMPERIALISM 0x0069af2c
char s_mcflavor_0069af2c[] = "";
// GLOBAL: IMPERIALISM 0x0069af30
char s_mcflavor_0069af30[] = "";
// GLOBAL: IMPERIALISM 0x0069af34
char s_mcflavor_0069af34[] = "";
// GLOBAL: IMPERIALISM 0x0069af38
char s_mcflavor_0069af38[] = "";
// GLOBAL: IMPERIALISM 0x0069af3c
char s_mcflavor_0069af3c[] = "";
// GLOBAL: IMPERIALISM 0x0069af40
char s_mcflavor_0069af40[] = "";
// GLOBAL: IMPERIALISM 0x0069af44
char s_mcflavor_0069af44[] = "";
// GLOBAL: IMPERIALISM 0x0069af48
char s_mcflavor_0069af48[] = "";
// GLOBAL: IMPERIALISM 0x0069af4c
char s_mcflavor_0069af4c[] = "";
// GLOBAL: IMPERIALISM 0x0069af50
char s_mcflavor_0069af50[] = "";
// GLOBAL: IMPERIALISM 0x0069af54
char s_mcflavor_0069af54[] = "";
// GLOBAL: IMPERIALISM 0x0069af58
char s_mcflavor_0069af58[] = "";
// GLOBAL: IMPERIALISM 0x0069af5c
char s_mcflavor_0069af5c[] = "";
// GLOBAL: IMPERIALISM 0x0069af60
char s_mcflavor_0069af60[] = "";
// GLOBAL: IMPERIALISM 0x0069af64
char s_mcflavor_0069af64[] = "";
// GLOBAL: IMPERIALISM 0x0069af68
char s_mcflavor_0069af68[] = "";
// GLOBAL: IMPERIALISM 0x0069af6c
char s_mcflavor_0069af6c[] = "";
// GLOBAL: IMPERIALISM 0x0069af70
char s_mcflavor_0069af70[] = "";
// GLOBAL: IMPERIALISM 0x0069af74
char s_mcflavor_0069af74[] = "";
// GLOBAL: IMPERIALISM 0x0069af78
char s_mcflavor_0069af78[] = "";
// GLOBAL: IMPERIALISM 0x0069af7c
char s_mcflavor_0069af7c[] = "";
// GLOBAL: IMPERIALISM 0x0069af80
char s_mcflavor_0069af80[] = "";
// GLOBAL: IMPERIALISM 0x0069af84
char s_mcflavor_0069af84[] = "";
// GLOBAL: IMPERIALISM 0x0069af88
char s_mcflavor_0069af88[] = "";
// GLOBAL: IMPERIALISM 0x0069af8c
char s_mcflavor_0069af8c[] = "";
// GLOBAL: IMPERIALISM 0x0069af90
char s_mcflavor_0069af90[] = "";
// GLOBAL: IMPERIALISM 0x0069af94
char s_mcflavor_0069af94[] = "";
// GLOBAL: IMPERIALISM 0x0069af98
char s_mcflavor_0069af98[] = "";
// GLOBAL: IMPERIALISM 0x0069af9c
char s_mcflavor_0069af9c[] = "";
// GLOBAL: IMPERIALISM 0x0069afa0
char s_mcflavor_0069afa0[] = "";
// GLOBAL: IMPERIALISM 0x0069afb0
char s_mcflavor_0069afb0[] = "";
// GLOBAL: IMPERIALISM 0x0069afc0
char s_mcflavor_0069afc0[] = "";
// GLOBAL: IMPERIALISM 0x0069afd0
char s_mcflavor_0069afd0[] = "";
// GLOBAL: IMPERIALISM 0x0069afdc
char s_mcflavor_0069afdc[] = "";
// GLOBAL: IMPERIALISM 0x0069afec
char s_mcflavor_0069afec[] = "";
// GLOBAL: IMPERIALISM 0x0069aff4
char s_mcflavor_0069aff4[] = "";
// GLOBAL: IMPERIALISM 0x0069b004
char s_mcflavor_0069b004[] = "";
// GLOBAL: IMPERIALISM 0x0069b010
char s_mcflavor_0069b010[] = "";
// GLOBAL: IMPERIALISM 0x0069b01c
char s_mcflavor_0069b01c[] = "";
// GLOBAL: IMPERIALISM 0x0069b020
char s_mcflavor_0069b020[] = "";
// GLOBAL: IMPERIALISM 0x0069b024
char s_mcflavor_0069b024[] = "";
// GLOBAL: IMPERIALISM 0x0069b028
char s_mcflavor_0069b028[] = "";
// GLOBAL: IMPERIALISM 0x0069b02c
char s_mcflavor_0069b02c[] = "";
// GLOBAL: IMPERIALISM 0x0069b030
char s_mcflavor_0069b030[] = "";
// GLOBAL: IMPERIALISM 0x0069b034
char s_mcflavor_0069b034[] = "";
// GLOBAL: IMPERIALISM 0x0069b038
char s_mcflavor_0069b038[] = "";
// GLOBAL: IMPERIALISM 0x0069b03c
char s_mcflavor_0069b03c[] = "";
// GLOBAL: IMPERIALISM 0x0069b040
char s_mcflavor_0069b040[] = "";
// GLOBAL: IMPERIALISM 0x0069b044
char s_mcflavor_0069b044[] = "";
// GLOBAL: IMPERIALISM 0x0069b048
char s_mcflavor_0069b048[] = "";
// GLOBAL: IMPERIALISM 0x0069b04c
char s_mcflavor_0069b04c[] = "";
// GLOBAL: IMPERIALISM 0x0069b050
char s_mcflavor_0069b050[] = "";
// GLOBAL: IMPERIALISM 0x0069b054
char s_mcflavor_0069b054[] = "";
// GLOBAL: IMPERIALISM 0x0069b058
char s_mcflavor_0069b058[] = "";
// GLOBAL: IMPERIALISM 0x0069b05c
char s_mcflavor_0069b05c[] = "";
// GLOBAL: IMPERIALISM 0x0069b060
char s_mcflavor_0069b060[] = "";
// GLOBAL: IMPERIALISM 0x0069b064
char s_mcflavor_0069b064[] = "";
// GLOBAL: IMPERIALISM 0x0069b068
char s_mcflavor_0069b068[] = "";
// GLOBAL: IMPERIALISM 0x0069b06c
char s_mcflavor_0069b06c[] = "";
// GLOBAL: IMPERIALISM 0x0069b070
char s_mcflavor_0069b070[] = "";
// GLOBAL: IMPERIALISM 0x0069b078
char s_mcflavor_0069b078[] = "";
// GLOBAL: IMPERIALISM 0x0069b07c
char s_mcflavor_0069b07c[] = "";
// GLOBAL: IMPERIALISM 0x0069b084
char s_mcflavor_0069b084[] = "";
// GLOBAL: IMPERIALISM 0x0069b088
char s_mcflavor_0069b088[] = "";
// GLOBAL: IMPERIALISM 0x0069b08c
char s_mcflavor_0069b08c[] = "";
// GLOBAL: IMPERIALISM 0x0069b090
char s_mcflavor_0069b090[] = "";
// GLOBAL: IMPERIALISM 0x0069b098
char s_mcflavor_0069b098[] = "";
// GLOBAL: IMPERIALISM 0x0069b09c
char s_mcflavor_0069b09c[] = "";
// GLOBAL: IMPERIALISM 0x0069b0a0
char s_mcflavor_0069b0a0[] = "";
// GLOBAL: IMPERIALISM 0x0069b0a4
char s_mcflavor_0069b0a4[] = "";
// GLOBAL: IMPERIALISM 0x0069b0a8
char s_mcflavor_0069b0a8[] = "";
// GLOBAL: IMPERIALISM 0x0069b0ac
char s_mcflavor_0069b0ac[] = "";
// GLOBAL: IMPERIALISM 0x0069b0b0
char s_mcflavor_0069b0b0[] = "";
// GLOBAL: IMPERIALISM 0x0069b0b4
char s_mcflavor_0069b0b4[] = "";
// GLOBAL: IMPERIALISM 0x0069b0b8
char s_mcflavor_0069b0b8[] = "";
// GLOBAL: IMPERIALISM 0x0069b0bc
char s_mcflavor_0069b0bc[] = "";
// GLOBAL: IMPERIALISM 0x0069b0c0
char s_mcflavor_0069b0c0[] = "";
// GLOBAL: IMPERIALISM 0x0069b0c4
char s_mcflavor_0069b0c4[] = "";
// GLOBAL: IMPERIALISM 0x0069b0c8
char s_mcflavor_0069b0c8[] = "";
// GLOBAL: IMPERIALISM 0x0069b0cc
char s_mcflavor_0069b0cc[] = "";
// GLOBAL: IMPERIALISM 0x0069b0d0
char s_mcflavor_0069b0d0[] = "";
// GLOBAL: IMPERIALISM 0x0069b0d4
char s_mcflavor_0069b0d4[] = "";
// GLOBAL: IMPERIALISM 0x0069b0d8
char s_mcflavor_0069b0d8[] = "";
// GLOBAL: IMPERIALISM 0x0069b0dc
char s_mcflavor_0069b0dc[] = "";
// GLOBAL: IMPERIALISM 0x0069b0e0
char s_mcflavor_0069b0e0[] = "";
// GLOBAL: IMPERIALISM 0x0069b0e4
char s_mcflavor_0069b0e4[] = "";
// GLOBAL: IMPERIALISM 0x0069b0e8
char s_mcflavor_0069b0e8[] = "";
// GLOBAL: IMPERIALISM 0x0069b0ec
char s_mcflavor_0069b0ec[] = "";
// GLOBAL: IMPERIALISM 0x0069b0f0
char s_mcflavor_0069b0f0[] = "";
// GLOBAL: IMPERIALISM 0x0069b0f4
char s_mcflavor_0069b0f4[] = "";
// GLOBAL: IMPERIALISM 0x0069b0f8
char s_mcflavor_0069b0f8[] = "";
// GLOBAL: IMPERIALISM 0x0069b100
char s_mcflavor_0069b100[] = "";
// GLOBAL: IMPERIALISM 0x0069b104
char s_mcflavor_0069b104[] = "";
// GLOBAL: IMPERIALISM 0x0069b108
char s_mcflavor_0069b108[] = "";
// GLOBAL: IMPERIALISM 0x0069b10c
char s_mcflavor_0069b10c[] = "";
// GLOBAL: IMPERIALISM 0x0069b110
char s_mcflavor_0069b110[] = "";
// GLOBAL: IMPERIALISM 0x0069b114
char s_mcflavor_0069b114[] = "";
// GLOBAL: IMPERIALISM 0x0069b118
char s_mcflavor_0069b118[] = "";
// GLOBAL: IMPERIALISM 0x0069b11c
char s_mcflavor_0069b11c[] = "";
// GLOBAL: IMPERIALISM 0x0069b120
char s_mcflavor_0069b120[] = "";
// GLOBAL: IMPERIALISM 0x0069b124
char s_mcflavor_0069b124[] = "";
// GLOBAL: IMPERIALISM 0x0069b128
char s_mcflavor_0069b128[] = "";
// GLOBAL: IMPERIALISM 0x0069b12c
char s_mcflavor_0069b12c[] = "";
// GLOBAL: IMPERIALISM 0x0069b130
char s_mcflavor_0069b130[] = "";
// GLOBAL: IMPERIALISM 0x0069b134
char s_mcflavor_0069b134[] = "";
// GLOBAL: IMPERIALISM 0x0069b138
char s_mcflavor_0069b138[] = "";
// GLOBAL: IMPERIALISM 0x0069b13c
char s_mcflavor_0069b13c[] = "";
// GLOBAL: IMPERIALISM 0x0069b14c
char s_mcflavor_0069b14c[] = "";
// GLOBAL: IMPERIALISM 0x0069b158
char s_mcflavor_0069b158[] = "";
// GLOBAL: IMPERIALISM 0x0069b15c
char s_mcflavor_0069b15c[] = "";
// GLOBAL: IMPERIALISM 0x0069b160
char s_mcflavor_0069b160[] = "";
// GLOBAL: IMPERIALISM 0x0069b164
char s_mcflavor_0069b164[] = "";
// GLOBAL: IMPERIALISM 0x0069b168
char s_mcflavor_0069b168[] = "";
// GLOBAL: IMPERIALISM 0x0069b16c
char s_mcflavor_0069b16c[] = "";
// GLOBAL: IMPERIALISM 0x0069b170
char s_mcflavor_0069b170[] = "";
// GLOBAL: IMPERIALISM 0x0069b174
char s_mcflavor_0069b174[] = "";
// GLOBAL: IMPERIALISM 0x0069b178
char s_mcflavor_0069b178[] = "";
// GLOBAL: IMPERIALISM 0x0069b17c
char s_mcflavor_0069b17c[] = "";
// GLOBAL: IMPERIALISM 0x0069b184
char s_mcflavor_0069b184[] = "";
// GLOBAL: IMPERIALISM 0x0069b188
char s_mcflavor_0069b188[] = "";
// GLOBAL: IMPERIALISM 0x0069b18c
char s_mcflavor_0069b18c[] = "";
// GLOBAL: IMPERIALISM 0x0069b190
char s_mcflavor_0069b190[] = "";
// GLOBAL: IMPERIALISM 0x0069b194
char s_mcflavor_0069b194[] = "";
// GLOBAL: IMPERIALISM 0x0069b198
char s_mcflavor_0069b198[] = "";
// GLOBAL: IMPERIALISM 0x0069b19c
char s_mcflavor_0069b19c[] = "";
// GLOBAL: IMPERIALISM 0x0069b1a0
char s_mcflavor_0069b1a0[] = "";
// GLOBAL: IMPERIALISM 0x0069b1a8
char s_mcflavor_0069b1a8[] = "";
// GLOBAL: IMPERIALISM 0x0069b1ac
char s_mcflavor_0069b1ac[] = "";
// GLOBAL: IMPERIALISM 0x0069b1b0
char s_mcflavor_0069b1b0[] = "";
// GLOBAL: IMPERIALISM 0x0069b1b4
char s_mcflavor_0069b1b4[] = "";
// GLOBAL: IMPERIALISM 0x0069b1b8
char s_mcflavor_0069b1b8[] = "";
// GLOBAL: IMPERIALISM 0x0069b1bc
char s_mcflavor_0069b1bc[] = "";
// GLOBAL: IMPERIALISM 0x0069b1c0
char s_mcflavor_0069b1c0[] = "";
// GLOBAL: IMPERIALISM 0x0069b1c4
char s_mcflavor_0069b1c4[] = "";
// GLOBAL: IMPERIALISM 0x0069b1cc
char s_mcflavor_0069b1cc[] = "";
// GLOBAL: IMPERIALISM 0x0069b1d0
char s_mcflavor_0069b1d0[] = "";
// GLOBAL: IMPERIALISM 0x0069b1d4
char s_mcflavor_0069b1d4[] = "";
// GLOBAL: IMPERIALISM 0x0069b1d8
char s_mcflavor_0069b1d8[] = "";
// GLOBAL: IMPERIALISM 0x0069b1dc
char s_mcflavor_0069b1dc[] = "";
// GLOBAL: IMPERIALISM 0x0069b1e0
char s_mcflavor_0069b1e0[] = "";
// GLOBAL: IMPERIALISM 0x0069b1e4
char s_mcflavor_0069b1e4[] = "";
// GLOBAL: IMPERIALISM 0x0069b1e8
char s_mcflavor_0069b1e8[] = "";
// GLOBAL: IMPERIALISM 0x0069b1ec
char s_mcflavor_0069b1ec[] = "";
// GLOBAL: IMPERIALISM 0x0069b1f0
char s_mcflavor_0069b1f0[] = "";
// GLOBAL: IMPERIALISM 0x0069b1f4
char s_mcflavor_0069b1f4[] = "";
// GLOBAL: IMPERIALISM 0x0069b1f8
char s_mcflavor_0069b1f8[] = "";
// GLOBAL: IMPERIALISM 0x0069b1fc
char s_mcflavor_0069b1fc[] = "";
// GLOBAL: IMPERIALISM 0x0069b204
char s_mcflavor_0069b204[] = "";
// GLOBAL: IMPERIALISM 0x0069b208
char s_mcflavor_0069b208[] = "";
// GLOBAL: IMPERIALISM 0x0069b20c
char s_mcflavor_0069b20c[] = "";
// GLOBAL: IMPERIALISM 0x0069b210
char s_mcflavor_0069b210[] = "";
// GLOBAL: IMPERIALISM 0x0069b214
char s_mcflavor_0069b214[] = "";
// GLOBAL: IMPERIALISM 0x0069b218
char s_mcflavor_0069b218[] = "";
// GLOBAL: IMPERIALISM 0x0069b21c
char s_mcflavor_0069b21c[] = "";
// GLOBAL: IMPERIALISM 0x0069b220
char s_mcflavor_0069b220[] = "";
// GLOBAL: IMPERIALISM 0x0069b224
char s_mcflavor_0069b224[] = "";
// GLOBAL: IMPERIALISM 0x0069b228
char s_mcflavor_0069b228[] = "";
// GLOBAL: IMPERIALISM 0x0069b22c
char s_mcflavor_0069b22c[] = "";
// GLOBAL: IMPERIALISM 0x0069b234
char s_mcflavor_0069b234[] = "";
// GLOBAL: IMPERIALISM 0x0069b238
char s_mcflavor_0069b238[] = "";
// GLOBAL: IMPERIALISM 0x0069b23c
char s_mcflavor_0069b23c[] = "";
// GLOBAL: IMPERIALISM 0x0069b240
char s_mcflavor_0069b240[] = "";
// GLOBAL: IMPERIALISM 0x0069b244
char s_mcflavor_0069b244[] = "";
// GLOBAL: IMPERIALISM 0x0069b248
char s_mcflavor_0069b248[] = "";
// GLOBAL: IMPERIALISM 0x0069b24c
char s_mcflavor_0069b24c[] = "";
// GLOBAL: IMPERIALISM 0x0069b254
char s_mcflavor_0069b254[] = "";
// GLOBAL: IMPERIALISM 0x0069b25c
char s_mcflavor_0069b25c[] = "";
// GLOBAL: IMPERIALISM 0x0069b260
char s_mcflavor_0069b260[] = "";
// GLOBAL: IMPERIALISM 0x0069b264
char s_mcflavor_0069b264[] = "";
// GLOBAL: IMPERIALISM 0x0069b268
char s_mcflavor_0069b268[] = "";
// GLOBAL: IMPERIALISM 0x0069b26c
char s_mcflavor_0069b26c[] = "";
// GLOBAL: IMPERIALISM 0x0069b270
char s_mcflavor_0069b270[] = "";
// GLOBAL: IMPERIALISM 0x0069b274
char s_mcflavor_0069b274[] = "";
// GLOBAL: IMPERIALISM 0x0069b278
char s_mcflavor_0069b278[] = "";
// GLOBAL: IMPERIALISM 0x0069b27c
char s_mcflavor_0069b27c[] = "";
// GLOBAL: IMPERIALISM 0x0069b280
char s_mcflavor_0069b280[] = "";
// GLOBAL: IMPERIALISM 0x0069b284
char s_mcflavor_0069b284[] = "";
// GLOBAL: IMPERIALISM 0x0069b288
char s_mcflavor_0069b288[] = "";
// GLOBAL: IMPERIALISM 0x0069b28c
char s_mcflavor_0069b28c[] = "";
// GLOBAL: IMPERIALISM 0x0069b290
char s_mcflavor_0069b290[] = "";
// GLOBAL: IMPERIALISM 0x0069b294
char s_mcflavor_0069b294[] = "";
// GLOBAL: IMPERIALISM 0x0069b298
char s_mcflavor_0069b298[] = "";
// GLOBAL: IMPERIALISM 0x0069b29c
char s_mcflavor_0069b29c[] = "";
// GLOBAL: IMPERIALISM 0x0069b2a0
char s_mcflavor_0069b2a0[] = "";
// GLOBAL: IMPERIALISM 0x0069b2a4
char s_mcflavor_0069b2a4[] = "";
// GLOBAL: IMPERIALISM 0x0069b2a8
char s_mcflavor_0069b2a8[] = "";
// GLOBAL: IMPERIALISM 0x0069b2ac
char s_mcflavor_0069b2ac[] = "";
// GLOBAL: IMPERIALISM 0x0069b2b0
char s_mcflavor_0069b2b0[] = "";
// GLOBAL: IMPERIALISM 0x0069b2b4
char s_mcflavor_0069b2b4[] = "";
// GLOBAL: IMPERIALISM 0x0069b2b8
char s_mcflavor_0069b2b8[] = "";
// GLOBAL: IMPERIALISM 0x0069b2bc
char s_mcflavor_0069b2bc[] = "";
// GLOBAL: IMPERIALISM 0x0069b2c0
char s_mcflavor_0069b2c0[] = "";
// GLOBAL: IMPERIALISM 0x0069b2c4
char s_mcflavor_0069b2c4[] = "";
// GLOBAL: IMPERIALISM 0x0069b2c8
char s_mcflavor_0069b2c8[] = "";
// GLOBAL: IMPERIALISM 0x0069b2cc
char s_mcflavor_0069b2cc[] = "";
// GLOBAL: IMPERIALISM 0x0069b2d0
char s_mcflavor_0069b2d0[] = "";
// GLOBAL: IMPERIALISM 0x0069b2d4
char s_mcflavor_0069b2d4[] = "";
// GLOBAL: IMPERIALISM 0x0069b2d8
char s_mcflavor_0069b2d8[] = "";
// GLOBAL: IMPERIALISM 0x0069b2dc
char s_mcflavor_0069b2dc[] = "";
// GLOBAL: IMPERIALISM 0x0069b2e0
char s_mcflavor_0069b2e0[] = "";
// GLOBAL: IMPERIALISM 0x0069b2e4
char s_mcflavor_0069b2e4[] = "";
// GLOBAL: IMPERIALISM 0x0069b2e8
char s_mcflavor_0069b2e8[] = "";
// GLOBAL: IMPERIALISM 0x0069b2f0
char s_mcflavor_0069b2f0[] = "";
// GLOBAL: IMPERIALISM 0x0069b2f8
char s_mcflavor_0069b2f8[] = "";
// GLOBAL: IMPERIALISM 0x0069b2fc
char s_mcflavor_0069b2fc[] = "";
// GLOBAL: IMPERIALISM 0x0069b304
char s_mcflavor_0069b304[] = "";
// GLOBAL: IMPERIALISM 0x0069b308
char s_mcflavor_0069b308[] = "";
// GLOBAL: IMPERIALISM 0x0069b30c
char s_mcflavor_0069b30c[] = "";
// GLOBAL: IMPERIALISM 0x0069b310
char s_mcflavor_0069b310[] = "";
// GLOBAL: IMPERIALISM 0x0069b314
char s_mcflavor_0069b314[] = "";
// GLOBAL: IMPERIALISM 0x0069b318
char s_mcflavor_0069b318[] = "";
// GLOBAL: IMPERIALISM 0x0069b31c
char s_mcflavor_0069b31c[] = "";
// GLOBAL: IMPERIALISM 0x0069b320
char s_mcflavor_0069b320[] = "";
// GLOBAL: IMPERIALISM 0x0069b324
char s_mcflavor_0069b324[] = "";
// GLOBAL: IMPERIALISM 0x0069b328
char s_mcflavor_0069b328[] = "";
// GLOBAL: IMPERIALISM 0x0069b32c
char s_mcflavor_0069b32c[] = "";
// GLOBAL: IMPERIALISM 0x0069b334
char s_mcflavor_0069b334[] = "";
// GLOBAL: IMPERIALISM 0x0069b338
char s_mcflavor_0069b338[] = "";
// GLOBAL: IMPERIALISM 0x0069b33c
char s_mcflavor_0069b33c[] = "";
// GLOBAL: IMPERIALISM 0x0069b340
char s_mcflavor_0069b340[] = "";
// GLOBAL: IMPERIALISM 0x0069b344
char s_mcflavor_0069b344[] = "";
// GLOBAL: IMPERIALISM 0x0069b348
char s_mcflavor_0069b348[] = "";
// GLOBAL: IMPERIALISM 0x0069b34c
char s_mcflavor_0069b34c[] = "";
// GLOBAL: IMPERIALISM 0x0069b350
char s_mcflavor_0069b350[] = "";
// GLOBAL: IMPERIALISM 0x0069b354
char s_mcflavor_0069b354[] = "";
// GLOBAL: IMPERIALISM 0x0069b358
char s_mcflavor_0069b358[] = "";
// GLOBAL: IMPERIALISM 0x0069b35c
char s_mcflavor_0069b35c[] = "";
// GLOBAL: IMPERIALISM 0x0069b360
char s_mcflavor_0069b360[] = "";
// GLOBAL: IMPERIALISM 0x0069b364
char s_mcflavor_0069b364[] = "";
// GLOBAL: IMPERIALISM 0x0069b368
char s_mcflavor_0069b368[] = "";
// GLOBAL: IMPERIALISM 0x0069b36c
char s_mcflavor_0069b36c[] = "";
// GLOBAL: IMPERIALISM 0x0069b370
char s_mcflavor_0069b370[] = "";
// GLOBAL: IMPERIALISM 0x0069b374
char s_mcflavor_0069b374[] = "";
// GLOBAL: IMPERIALISM 0x0069b378
char s_mcflavor_0069b378[] = "";
// GLOBAL: IMPERIALISM 0x0069b37c
char s_mcflavor_0069b37c[] = "";
// GLOBAL: IMPERIALISM 0x0069b380
char s_mcflavor_0069b380[] = "";
// GLOBAL: IMPERIALISM 0x0069b384
char s_mcflavor_0069b384[] = "";
// GLOBAL: IMPERIALISM 0x0069b388
char s_mcflavor_0069b388[] = "";
// GLOBAL: IMPERIALISM 0x0069b38c
char s_mcflavor_0069b38c[] = "";
// GLOBAL: IMPERIALISM 0x0069b390
char s_mcflavor_0069b390[] = "";
// GLOBAL: IMPERIALISM 0x0069b394
char s_mcflavor_0069b394[] = "";
// GLOBAL: IMPERIALISM 0x0069b398
char s_mcflavor_0069b398[] = "";
// GLOBAL: IMPERIALISM 0x0069b39c
char s_mcflavor_0069b39c[] = "";
// GLOBAL: IMPERIALISM 0x0069b3a0
char s_mcflavor_0069b3a0[] = "";
// GLOBAL: IMPERIALISM 0x0069b3a4
char s_mcflavor_0069b3a4[] = "";
// GLOBAL: IMPERIALISM 0x0069b3a8
char s_mcflavor_0069b3a8[] = "";
// GLOBAL: IMPERIALISM 0x0069b3ac
char s_mcflavor_0069b3ac[] = "";
// GLOBAL: IMPERIALISM 0x0069b3b0
char s_mcflavor_0069b3b0[] = "";
// GLOBAL: IMPERIALISM 0x0069b3b4
char s_mcflavor_0069b3b4[] = "";
// GLOBAL: IMPERIALISM 0x0069b3b8
char s_mcflavor_0069b3b8[] = "";
// GLOBAL: IMPERIALISM 0x0069b3bc
char s_mcflavor_0069b3bc[] = "";
// GLOBAL: IMPERIALISM 0x0069b3c4
char s_mcflavor_0069b3c4[] = "";
// GLOBAL: IMPERIALISM 0x0069b3c8
char s_mcflavor_0069b3c8[] = "";
// GLOBAL: IMPERIALISM 0x0069b3cc
char s_mcflavor_0069b3cc[] = "";
// GLOBAL: IMPERIALISM 0x0069b3d0
char s_mcflavor_0069b3d0[] = "";
// GLOBAL: IMPERIALISM 0x0069b3d4
char s_mcflavor_0069b3d4[] = "";
// GLOBAL: IMPERIALISM 0x0069b3dc
char s_mcflavor_0069b3dc[] = "";
// GLOBAL: IMPERIALISM 0x0069b3e0
char s_mcflavor_0069b3e0[] = "";
// GLOBAL: IMPERIALISM 0x0069b3e4
char s_mcflavor_0069b3e4[] = "";
// GLOBAL: IMPERIALISM 0x0069b3e8
char s_mcflavor_0069b3e8[] = "";
// GLOBAL: IMPERIALISM 0x0069b3ec
char s_mcflavor_0069b3ec[] = "";
// GLOBAL: IMPERIALISM 0x0069b3f0
char s_mcflavor_0069b3f0[] = "";
// GLOBAL: IMPERIALISM 0x0069b3f4
char s_mcflavor_0069b3f4[] = "";
// GLOBAL: IMPERIALISM 0x0069b3f8
char s_mcflavor_0069b3f8[] = "";
// GLOBAL: IMPERIALISM 0x0069b400
char s_mcflavor_0069b400[] = "";
// GLOBAL: IMPERIALISM 0x0069b404
char s_mcflavor_0069b404[] = "";
// GLOBAL: IMPERIALISM 0x0069b408
char s_mcflavor_0069b408[] = "";
// GLOBAL: IMPERIALISM 0x0069b40c
char s_mcflavor_0069b40c[] = "";
// GLOBAL: IMPERIALISM 0x0069b410
char s_mcflavor_0069b410[] = "";
// GLOBAL: IMPERIALISM 0x0069b418
char s_mcflavor_0069b418[] = "";
// GLOBAL: IMPERIALISM 0x0069b41c
char s_mcflavor_0069b41c[] = "";
// GLOBAL: IMPERIALISM 0x0069b420
char s_mcflavor_0069b420[] = "";
// GLOBAL: IMPERIALISM 0x0069b424
char s_mcflavor_0069b424[] = "";
// GLOBAL: IMPERIALISM 0x0069b428
char s_mcflavor_0069b428[] = "";
// GLOBAL: IMPERIALISM 0x0069b42c
char s_mcflavor_0069b42c[] = "";
// GLOBAL: IMPERIALISM 0x0069b430
char s_mcflavor_0069b430[] = "";
// GLOBAL: IMPERIALISM 0x0069b434
char s_mcflavor_0069b434[] = "";
// GLOBAL: IMPERIALISM 0x0069b438
char s_mcflavor_0069b438[] = "";
// GLOBAL: IMPERIALISM 0x0069b43c
char s_mcflavor_0069b43c[] = "";
// GLOBAL: IMPERIALISM 0x0069b440
char s_mcflavor_0069b440[] = "";
// GLOBAL: IMPERIALISM 0x0069b444
char s_mcflavor_0069b444[] = "";
// GLOBAL: IMPERIALISM 0x0069b448
char s_mcflavor_0069b448[] = "";
// GLOBAL: IMPERIALISM 0x0069b44c
char s_mcflavor_0069b44c[] = "";
// GLOBAL: IMPERIALISM 0x0069b454
char s_mcflavor_0069b454[] = "";
// GLOBAL: IMPERIALISM 0x0069b458
char s_mcflavor_0069b458[] = "";
// GLOBAL: IMPERIALISM 0x0069b45c
char s_mcflavor_0069b45c[] = "";
// GLOBAL: IMPERIALISM 0x0069b460
char s_mcflavor_0069b460[] = "";
// GLOBAL: IMPERIALISM 0x0069b464
char s_mcflavor_0069b464[] = "";
// GLOBAL: IMPERIALISM 0x0069b468
char s_mcflavor_0069b468[] = "";
// GLOBAL: IMPERIALISM 0x0069b46c
char s_mcflavor_0069b46c[] = "";
// GLOBAL: IMPERIALISM 0x0069b470
char s_mcflavor_0069b470[] = "";
// GLOBAL: IMPERIALISM 0x0069b474
char s_mcflavor_0069b474[] = "";
// GLOBAL: IMPERIALISM 0x0069b478
char s_mcflavor_0069b478[] = "";
// GLOBAL: IMPERIALISM 0x0069b47c
char s_mcflavor_0069b47c[] = "";
// GLOBAL: IMPERIALISM 0x0069b480
char s_mcflavor_0069b480[] = "";
// GLOBAL: IMPERIALISM 0x0069b484
char s_mcflavor_0069b484[] = "";
// GLOBAL: IMPERIALISM 0x0069b488
char s_mcflavor_0069b488[] = "";
// GLOBAL: IMPERIALISM 0x0069b48c
char s_mcflavor_0069b48c[] = "";
// GLOBAL: IMPERIALISM 0x0069b490
char s_mcflavor_0069b490[] = "";
// GLOBAL: IMPERIALISM 0x0069b498
char s_mcflavor_0069b498[] = "";
// GLOBAL: IMPERIALISM 0x0069b49c
char s_mcflavor_0069b49c[] = "";
// GLOBAL: IMPERIALISM 0x0069b4a0
char s_mcflavor_0069b4a0[] = "";
// GLOBAL: IMPERIALISM 0x0069b4a4
char s_mcflavor_0069b4a4[] = "";
// GLOBAL: IMPERIALISM 0x0069b4a8
char s_mcflavor_0069b4a8[] = "";
// GLOBAL: IMPERIALISM 0x0069b4ac
char s_mcflavor_0069b4ac[] = "";
// GLOBAL: IMPERIALISM 0x0069b4b0
char s_mcflavor_0069b4b0[] = "";
// GLOBAL: IMPERIALISM 0x0069b4b4
char s_mcflavor_0069b4b4[] = "";
// GLOBAL: IMPERIALISM 0x0069b4b8
char s_mcflavor_0069b4b8[] = "";
// GLOBAL: IMPERIALISM 0x0069b4bc
char s_mcflavor_0069b4bc[] = "";
// GLOBAL: IMPERIALISM 0x0069b4c4
char s_mcflavor_0069b4c4[] = "";
// GLOBAL: IMPERIALISM 0x0069b4c8
char s_mcflavor_0069b4c8[] = "";
// GLOBAL: IMPERIALISM 0x0069b4cc
char s_mcflavor_0069b4cc[] = "";
// GLOBAL: IMPERIALISM 0x0069b4d0
char s_mcflavor_0069b4d0[] = "";
// GLOBAL: IMPERIALISM 0x0069b4d4
char s_mcflavor_0069b4d4[] = "";
// GLOBAL: IMPERIALISM 0x0069b4d8
char s_mcflavor_0069b4d8[] = "";
// GLOBAL: IMPERIALISM 0x0069b4dc
char s_mcflavor_0069b4dc[] = "";
// GLOBAL: IMPERIALISM 0x0069b4e0
char s_mcflavor_0069b4e0[] = "";
// GLOBAL: IMPERIALISM 0x0069b4e4
char s_mcflavor_0069b4e4[] = "";
// GLOBAL: IMPERIALISM 0x0069b4e8
char s_mcflavor_0069b4e8[] = "";
// GLOBAL: IMPERIALISM 0x0069b4ec
char s_mcflavor_0069b4ec[] = "";
// GLOBAL: IMPERIALISM 0x0069b4f0
char s_mcflavor_0069b4f0[] = "";
// GLOBAL: IMPERIALISM 0x0069b4f4
char s_mcflavor_0069b4f4[] = "";
// GLOBAL: IMPERIALISM 0x0069b4f8
char s_mcflavor_0069b4f8[] = "";
// GLOBAL: IMPERIALISM 0x0069b4fc
char s_mcflavor_0069b4fc[] = "";
// GLOBAL: IMPERIALISM 0x0069b500
char s_mcflavor_0069b500[] = "";
// GLOBAL: IMPERIALISM 0x0069b504
char s_mcflavor_0069b504[] = "";
// GLOBAL: IMPERIALISM 0x0069b508
char s_mcflavor_0069b508[] = "";
// GLOBAL: IMPERIALISM 0x0069b50c
char s_mcflavor_0069b50c[] = "";
// GLOBAL: IMPERIALISM 0x0069b510
char s_mcflavor_0069b510[] = "";
// GLOBAL: IMPERIALISM 0x0069b514
char s_mcflavor_0069b514[] = "";
// GLOBAL: IMPERIALISM 0x0069b518
char s_mcflavor_0069b518[] = "";
// GLOBAL: IMPERIALISM 0x0069b51c
char s_mcflavor_0069b51c[] = "";
// GLOBAL: IMPERIALISM 0x0069b520
char s_mcflavor_0069b520[] = "";
// GLOBAL: IMPERIALISM 0x0069b524
char s_mcflavor_0069b524[] = "";
// GLOBAL: IMPERIALISM 0x0069b528
char s_mcflavor_0069b528[] = "";
// GLOBAL: IMPERIALISM 0x0069b52c
char s_mcflavor_0069b52c[] = "";
// GLOBAL: IMPERIALISM 0x0069b534
char s_mcflavor_0069b534[] = "";
// GLOBAL: IMPERIALISM 0x0069b53c
char s_mcflavor_0069b53c[] = "";
// GLOBAL: IMPERIALISM 0x0069b544
char s_mcflavor_0069b544[] = "";
// GLOBAL: IMPERIALISM 0x0069b54c
char s_mcflavor_0069b54c[] = "";
// GLOBAL: IMPERIALISM 0x0069b554
char s_mcflavor_0069b554[] = "";
// GLOBAL: IMPERIALISM 0x0069b55c
char s_mcflavor_0069b55c[] = "";
// GLOBAL: IMPERIALISM 0x0069b564
char s_mcflavor_0069b564[] = "";
// GLOBAL: IMPERIALISM 0x0069b56c
char s_mcflavor_0069b56c[] = "";
// GLOBAL: IMPERIALISM 0x0069b57c
char s_mcflavor_0069b57c[] = "";
// GLOBAL: IMPERIALISM 0x0069b584
char s_mcflavor_0069b584[] = "";
// GLOBAL: IMPERIALISM 0x0069b590
char s_mcflavor_0069b590[] = "";
// GLOBAL: IMPERIALISM 0x0069b598
char s_mcflavor_0069b598[] = "";
// GLOBAL: IMPERIALISM 0x0069b59c
char s_mcflavor_0069b59c[] = "";
// GLOBAL: IMPERIALISM 0x0069b5a4
char s_mcflavor_0069b5a4[] = "";
// GLOBAL: IMPERIALISM 0x0069b5ac
char s_mcflavor_0069b5ac[] = "";
// GLOBAL: IMPERIALISM 0x0069b5b8
char s_mcflavor_0069b5b8[] = "";
// GLOBAL: IMPERIALISM 0x0069b5c0
char s_mcflavor_0069b5c0[] = "";
// GLOBAL: IMPERIALISM 0x0069b5c4
char s_mcflavor_0069b5c4[] = "";
// GLOBAL: IMPERIALISM 0x0069b5cc
char s_mcflavor_0069b5cc[] = "";
// GLOBAL: IMPERIALISM 0x0069b5d4
char s_mcflavor_0069b5d4[] = "";
// GLOBAL: IMPERIALISM 0x0069b5dc
char s_mcflavor_0069b5dc[] = "";
// GLOBAL: IMPERIALISM 0x0069b5e4
char s_mcflavor_0069b5e4[] = "";
// GLOBAL: IMPERIALISM 0x0069b5ec
char s_mcflavor_0069b5ec[] = "";
// GLOBAL: IMPERIALISM 0x0069b5f4
char s_mcflavor_0069b5f4[] = "";
// GLOBAL: IMPERIALISM 0x0069b5fc
char s_mcflavor_0069b5fc[] = "";
// GLOBAL: IMPERIALISM 0x0069b604
char s_mcflavor_0069b604[] = "";
// GLOBAL: IMPERIALISM 0x0069b60c
char s_mcflavor_0069b60c[] = "";
// GLOBAL: IMPERIALISM 0x0069b614
char s_mcflavor_0069b614[] = "";
// GLOBAL: IMPERIALISM 0x0069b61c
char s_mcflavor_0069b61c[] = "";
// GLOBAL: IMPERIALISM 0x0069b624
char s_mcflavor_0069b624[] = "";
// GLOBAL: IMPERIALISM 0x0069b628
char s_mcflavor_0069b628[] = "";
// GLOBAL: IMPERIALISM 0x0069b630
char s_mcflavor_0069b630[] = "";
// GLOBAL: IMPERIALISM 0x0069b638
char s_mcflavor_0069b638[] = "";
// GLOBAL: IMPERIALISM 0x0069b640
char s_mcflavor_0069b640[] = "";
// GLOBAL: IMPERIALISM 0x0069b7fc
char s_Data_scores_dat_0069b7fc[] = "Data\\scores.dat";
