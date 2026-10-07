class TControl;
class TView;
class TInfoBarText;

#include "game/nation_domain_types.h"
#include "game/tactical/TArmyPlayer.h"
#include "game/resource_manifest_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/mfc.h"
#include "game/core/global_data_tables.h"
#include "game/globals/mapped_flavor_literals.h"
#include "game/map/sea_geometry.h"
#include "game/app_init_globals.h"
#include "game/ui_core/TViewMgr.h"
#include "game/net/TNetMgr.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/app/TAnimator.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/quickdraw_types.h"
#include "game/gfx/TResourceMgr.h"
#include "game/gfx/TBackdropWindow.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/globals/view_registries.h"

static inline double DefaultGfxCoordinateScale() {
  return 0.015625;
}

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// GLOBAL: IMPERIALISM 0x006a4310
TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount] = {0};
// GLOBAL: IMPERIALISM 0x006a2158
TDisplayMgr* g_pDisplayMgr = 0;
// GLOBAL: IMPERIALISM 0x006a2228
CPoint g_ptUiAnimatorSurfaceBounds(0x80, 0x80);
// GLOBAL: IMPERIALISM 0x006a224c
bool g_bStrategicMapSelectionOverlayPhase = false;
// GLOBAL: IMPERIALISM 0x00695934
int g_nIdleMeAnimationNextRegistryTag = kManifestTagAUT0;
// GLOBAL: IMPERIALISM 0x006a21a8
TMacViewMgr* g_pMacViewMgr = 0;
// GLOBAL: IMPERIALISM 0x006a21bc
TViewMgr* g_pViewMgr = 0;
// GLOBAL: IMPERIALISM 0x006a2050
TBackdropWindow* g_pActiveBackdropWindow = 0;
// GLOBAL: IMPERIALISM 0x006a2054
CWaitCursor* g_pBackdropWaitCursor = 0;
// GLOBAL: IMPERIALISM 0x006a2148
TAssetMgr* g_pAssetMgr = 0;
// GLOBAL: IMPERIALISM 0x006a327c
TLanguageMgr* g_pLanguageMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e0
TAnimator* g_pUiAnimator = 0;

// GLOBAL: IMPERIALISM 0x006a15cc
int g_diplomacyDialogAssertGuard = 0;

// ResourceMgr.cpp diagnostic gates used by the palette-resource overloads.
// GLOBAL: IMPERIALISM 0x006a1e50
int g_paletteResourceNameAssertGate = 0;
// GLOBAL: IMPERIALISM 0x006a1e54
int g_paletteResourceIdAssertGate = 0;

extern "C" {
// GLOBAL: IMPERIALISM 0x006951cc
extern const char g_szPaletteResourceType[] = "PALETTE";
// GLOBAL: IMPERIALISM 0x006951d8
extern const char g_szResourceMgrSourcePath[] = "D:\\Ambit\\ResourceMgr.cpp";
// GLOBAL: IMPERIALISM 0x006951f8
extern const char g_szPaletteResourceIdFormat[] = "#%lu";
}

// GLOBAL: IMPERIALISM 0x006a1e78
TTraceDialog g_debugTraceDialog(0);

extern "C" {

// GLOBAL: IMPERIALISM 0x0066efd0
const unsigned int g_strategicMapStatusIconTagTable[18] = {
    kControlTagRs0Sp, kControlTagRs1Sp, kControlTagRs2Sp,
    kControlTagRs3Sp, kControlTagRs4Sp, kControlTagRs5Sp,
    kControlTagRs6Sp, kControlTagMa0Sp, kControlTagMa1Sp,
    kControlTagMa2Sp, kControlTagMa3Sp, kControlTagMa4Sp,
    kControlTagMa5Sp, kControlTagGd0Sp, kControlTagGd1Sp,
    kControlTagGd2Sp, kControlTagGd3Sp, 0};

// Diplomacy globals
// GLOBAL: IMPERIALISM 0x006a4280
TMinor* g_apSecondaryNationStateSlots[36] = {0};
// GLOBAL: IMPERIALISM 0x006a4370
TGreatPower* g_apNationStates[kMajorNationCount] = {0};
// GLOBAL: IMPERIALISM 0x006a20f8
TSimMgr* g_pSimMgr = 0;
// GLOBAL: IMPERIALISM 0x006a21b8
THelpMgr* g_pHelpMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e8
TNewsMgr* g_pNewsMgr = 0;
// GLOBAL: IMPERIALISM 0x006a1344
TAmbitApplication* g_pAmbitApplication = 0;
// GLOBAL: IMPERIALISM 0x006a43c8
TMultiplayerMgr* g_pGameFlowState = 0;
// GLOBAL: IMPERIALISM 0x006a43d0
TDiplomacyMgr* g_pDiplomacyTurnStateManager = 0;
// GLOBAL: IMPERIALISM 0x006a43e4
TNavyMgr* g_pNavyOrderManager = 0;
// GLOBAL: IMPERIALISM 0x006a3ebc
extern "C" TAdmiral* g_pNavySecondaryOrderListHead = 0;
// GLOBAL: IMPERIALISM 0x006a3edc
extern "C" TShip* g_pNavyPrimaryOrderListHead = 0;
// GLOBAL: IMPERIALISM 0x006a3338
TArmyMgr* g_pMapContextActionManager = 0;

// GLOBAL: IMPERIALISM 0x00695428
extern const unsigned char g_MapContextStaticTable_00695428[0x20] = {
    0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x0064dc30
char* g_pBattleReportSharedText = g_szEmptyString;

// GLOBAL: IMPERIALISM 0x00662b90
char* g_pSmallViewsEmptyText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0064cb18
char* g_pMiniCivSharedText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0065c830
char* g_pShipFractionSharedText = g_szEmptyString;

// GLOBAL: IMPERIALISM 0x00654ec8
char* g_pDiplomacyPanelEmptyText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0065c160
char* g_pLoungeLocalPlayerNameSharedText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x00668b88
char* g_pStatusPictureMainSharedText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x00695448
extern const signed char g_MapContextStaticTable_00695448[0x20] = {
    1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a21c0
int g_lastEdgeAutoScrollTick16 = 0;
// GLOBAL: IMPERIALISM 0x00695278
int g_nSaveFormatVersion = -1;
// File header emitted by TAmbitFileBasedDocument::DoWrite and validated by DoRead.
// GLOBAL: IMPERIALISM 0x0064c094
extern const int g_nAmbitSaveFileMagic = kControlTagAMBI;
// GLOBAL: IMPERIALISM 0x0064c098
extern const int g_nCurrentAmbitSaveFormatVersion = 0x3e;
// GLOBAL: IMPERIALISM 0x0069527c
extern const char g_szUAmbitSourcePath[] = "D:\\Ambit\\Cross\\UAmbit.cpp";
// Per-great-power quarter phase used to stagger the diplomacy planning pass.
// GLOBAL: IMPERIALISM 0x00697818
extern const short g_aDiplomacyPlanningQuarterPhaseByNation[kMajorNationCount] = {0, 3, 1, 2,
                                                                                  1, 2, 0};
// GLOBAL: IMPERIALISM 0x00662978
extern const unsigned int g_anScenarioScriptInstructionTags[27] = {
    kManifestTagLabo, kManifestTagCapa, kManifestTagWare, kControlTagArmy,  kManifestTagCivi,
    kControlTagShip,  kControlTagTran,  kManifestTagDeve, kSummaryTagRail,  kControlTagPort,
    kManifestTagTech, kControlTagPric,  kManifestTagEmba, kManifestTagSubs, kControlTagTrea,
    kControlTagYear,  kControlTagProv,  kControlTagZone,  kManifestTagCnam, kControlTagRela,
    kManifestTagPnam, kControlTagCash,  kControlTagFlag,  kManifestTagTyer, kManifestTagTbar,
    kManifestTagTclr, kControlTagCoun,
};
// GLOBAL: IMPERIALISM 0x00698b50
void (TSimMgr::* g_apfnScenarioScriptInstructionHandlers[27])(STurnInstructionCursor*) = {
    &TSimMgr::ScSetLabor,        &TSimMgr::ScSetCapacity,     &TSimMgr::ScSetWarehouse,
    &TSimMgr::ScAddArmy,         &TSimMgr::ScAddCivilian,     &TSimMgr::ScAddShip,
    &TSimMgr::ScSetTransport,    &TSimMgr::ScSetDevLevel,     &TSimMgr::ScAddRailhead,
    &TSimMgr::ScAddPort,         &TSimMgr::ScAddTech,         &TSimMgr::ScSetPrice,
    &TSimMgr::ScSetEmbassy,      &TSimMgr::ScSetSubsidy,      &TSimMgr::ScSetTreaty,
    &TSimMgr::ScSetYear,         &TSimMgr::ScSetProvince,     &TSimMgr::ScSetSeazoneName,
    &TSimMgr::ScSetCountryName,  &TSimMgr::ScSetRelationship, &TSimMgr::ScSetProvinceName,
    &TSimMgr::ScSetTreasury,     &TSimMgr::ScSetFlags,        &TSimMgr::ScSetTechDate,
    &TSimMgr::ScSetTransportBar, &TSimMgr::ScClearTransport,  &TSimMgr::ScSetCouncilMeeting,
};
// GLOBAL: IMPERIALISM 0x006a4398
bool g_bScenarioScriptTerminationRequested = false;
// GLOBAL: IMPERIALISM 0x006a43b8
int g_nScenarioScriptInstructionCount = 0;
// GLOBAL: IMPERIALISM 0x006a3ee0
int g_UnknownMapOrderExecutionGuard = 0;
// GLOBAL: IMPERIALISM 0x006a30b4
int g_colorFillAssertGuard = 0;
// GLOBAL: IMPERIALISM 0x00694250
char g_szLiteralL[] = "L";
// GLOBAL: IMPERIALISM 0x00694254
char g_szCmdSwitchLangQuit[] = "L!";
// The MFC application singleton (&theApp), cached by InitInstance (0x412dc0).
// GLOBAL: IMPERIALISM 0x006a1348
class ImperialismApp* g_pImperialismApp = 0;
// GLOBAL: IMPERIALISM 0x006a1350
int g_nStartupAutoResolutionMode = 0;
// Previous CRT new-handler returned by _set_new_handler at startup (write-only).
// GLOBAL: IMPERIALISM 0x006a1354
_PNH g_pfnPreviousNewHandler = 0;
// GLOBAL: IMPERIALISM 0x006a1358
void* g_pAmbitDeveloperAssertProbe = 0;

// GLOBAL: IMPERIALISM 0x006950ac
int g_McAppUiActiveFlag = 1;
// GLOBAL: IMPERIALISM 0x006a1af8
int g_McAppUiDrawGate = 0;
// GLOBAL: IMPERIALISM 0x006a1ae0
int g_McAppUiFlag_006A1AE0 = 0;
// GLOBAL: IMPERIALISM 0x006a1ae4
int g_McAppUiFlag_006A1AE4 = 0;
// GLOBAL: IMPERIALISM 0x006a1afc
int g_McAppUiFlag_006A1AFC = 0;
// GLOBAL: IMPERIALISM 0x006a1b00
int g_McAppUiFlag_006A1B00 = 0;
// GLOBAL: IMPERIALISM 0x006a1af0
int g_McAppUiUpdateWindowRecursionGuard = 0;
// GLOBAL: IMPERIALISM 0x006a1af4
TView* g_McAppUiActiveRenderContext = 0;
// GLOBAL: IMPERIALISM 0x006a1a60
int g_McAppUiDefaultPosX = 0;
// GLOBAL: IMPERIALISM 0x006a1a64
int g_McAppUiDefaultPosY = 0;
// GLOBAL: IMPERIALISM 0x006a1a68
TMouseCaptureState g_McAppMouseCaptureState;
// GLOBAL: IMPERIALISM 0x006a1adc
unsigned int g_McAppUiMouseCaptureTimerId = 0;
// GLOBAL: IMPERIALISM 0x006950b0
char g_szMcAppUiSourcePath[] = "D:\\Ambit\\McAppUI.cpp";
// GLOBAL: IMPERIALISM 0x00695168
char g_szQuickDrawSourcePath[] = "D:\\Ambit\\QuickDraw.cpp";
// GLOBAL: IMPERIALISM 0x00695200
char g_szTraceLineBreakChars[] = "\n\r";
// GLOBAL: IMPERIALISM 0x00694354
char g_szUiPlaceholderStaticText[] = "Static Text";
// GLOBAL: IMPERIALISM 0x00694378
char g_szUiPlaceholderZero[] = "0";
// GLOBAL: IMPERIALISM 0x006943b0
char g_szUiPlaceholderTreasury[] = "$55,555";
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
char g_szUiPlaceholderSeason[] = "Winter, 1888";
// GLOBAL: IMPERIALISM 0x00694a98
char g_szUiPlaceholderSampleText[] = "Sample Text 1\n2\n3\n4\n5\n6\n7\n8";
// GLOBAL: IMPERIALISM 0x00694c50
int g_useCompatibleBitmapBlit = 1;
// GLOBAL: IMPERIALISM 0x006949e0
char g_szNewGameAllAutoGPs[] = "All AutoGP's";
// GLOBAL: IMPERIALISM 0x006949f0
char g_szNewGameNamesRandom[] = "Random";
// GLOBAL: IMPERIALISM 0x006949f8
char g_szNewGameNamesHistorical[] = "Historical";
// GLOBAL: IMPERIALISM 0x00694a08
char g_szNewGameNamesLabel[] = "Names:";
// GLOBAL: IMPERIALISM 0x00694a10
char g_szNewGameDifficultySetting[] = "Difficulty Setting";
// GLOBAL: IMPERIALISM 0x00694a28
char g_szNewGameDifficultyNighOnImpossible[] = "Nigh-On Impossible";
// GLOBAL: IMPERIALISM 0x00694a40
char g_szNewGameDifficultyHard[] = "Hard";
// GLOBAL: IMPERIALISM 0x00694a48
char g_szNewGameDifficultyNormal[] = "Normal";
// GLOBAL: IMPERIALISM 0x00694a50
char g_szNewGameDifficultyEasy[] = "Easy";
// GLOBAL: IMPERIALISM 0x00694a58
char g_szNewGameDifficultyIntroductory[] = "Introductory";
// GLOBAL: IMPERIALISM 0x00694a68
char g_szNewGameScenarioPlaceholderTitle[] = "Revenge of the Patagonians";
// GLOBAL: IMPERIALISM 0x00694a88
char g_szNewGameGameNameLabel[] = "Game name:";
// Trade-board screen labels (InitializeTradeScreenBitmapControls, events 0x7d9/0x7da).
// GLOBAL: IMPERIALISM 0x006948a4
char g_szUiOrdersLabel[] = "Orders";
// GLOBAL: IMPERIALISM 0x00694abc
char g_szUiPlaceholder185[] = "185";
// GLOBAL: IMPERIALISM 0x00694ac0
char g_szUiQuantityToOfferLabel[] = "Quantity to Offer";
// GLOBAL: IMPERIALISM 0x00694ad8
char g_szUiAvailableLabel[] = "Available";
// GLOBAL: IMPERIALISM 0x00694ae4
char g_szUiPriceLabel[] = "Price";
// GLOBAL: IMPERIALISM 0x00694aec
char g_szUiCommodityLabel[] = "Commodity";
// GLOBAL: IMPERIALISM 0x00694af8
char g_szUiBoardOfTradeLabel[] = "Board of Trade";

// Default text baked into the event 0x3ba planet-name dialog.
// GLOBAL: IMPERIALISM 0x00694528
char g_szUiDefaultPlanetName[] = "Skyron";
// GLOBAL: IMPERIALISM 0x00694530
char g_szUiPickAPlanet[] = "Pick a planet";
// GLOBAL: IMPERIALISM 0x00694540
char g_szUiAsEstimatedBy[] = "as estimated by";
// GLOBAL: IMPERIALISM 0x00694554
char g_szUiForeignShippingObserved[] = "Foreign Shipping Observed";
// GLOBAL: IMPERIALISM 0x00694574
char g_szUiHalfDozenShips[] = "\xa5 Half a dozen Ships-of-the-Line\n2\n3\n4";
// GLOBAL: IMPERIALISM 0x006945a4
char g_szUiNavalForcesReportOf[] = "Report of the naval forces of";
// GLOBAL: IMPERIALISM 0x006945c8
char g_szUiPlaceholderPont[] = "Pont";
// GLOBAL: IMPERIALISM 0x006945d0
char g_szUiForeignFleetReport[] = "Foreign Fleet Report";
// GLOBAL: IMPERIALISM 0x006945ec
char g_szUiTraderIndiamen[] = "1 trader, 6 indiamen";
// GLOBAL: IMPERIALISM 0x00694608
char g_szUiStoppedFromTrade[] = "were stopped from completing their trade";
// GLOBAL: IMPERIALISM 0x0069463c
char g_szUiPlaceholderPokei[] = "Pokei";
// GLOBAL: IMPERIALISM 0x00694644
char g_szUiToLabel[] = "to";
// GLOBAL: IMPERIALISM 0x00694648
char g_szUiItemLabel[] = "item";
// GLOBAL: IMPERIALISM 0x00694650
char g_szUiCarryingCargoOf[] = "carrying a cargo of";
// GLOBAL: IMPERIALISM 0x00694668
char g_szUiOwnrTag[] = "ownr";
// GLOBAL: IMPERIALISM 0x00694670
char g_szUiMerchantsBelongingTo[] = "Merchants belonging to";
// GLOBAL: IMPERIALISM 0x0069468c
char g_szUiAndConsistingOf[] = "and consisting of";
// GLOBAL: IMPERIALISM 0x006946a4
char g_szUiByTaskForceCommandedBy[] = "by a task force commanded by";
// GLOBAL: IMPERIALISM 0x006946c8
char g_szUiAdmiralKirk[] = " Adm. James T. Kirk of the USS Enterprise";
// GLOBAL: IMPERIALISM 0x006946fc
char g_szUiInThe[] = "in the";
// GLOBAL: IMPERIALISM 0x00694704
char g_szUiSeaOfOblongata[] = "Sea of Oblongata";
// GLOBAL: IMPERIALISM 0x00694718
char g_szUiThreeVessels[] = "3 vessels";
// GLOBAL: IMPERIALISM 0x00694724
char g_szUiResultOfSuccessful[] = "A result of a successful";
// GLOBAL: IMPERIALISM 0x00694744
char g_szUiBlockadeLabel[] = "Blockade";
// GLOBAL: IMPERIALISM 0x00694750
char g_szUiEnemyTradeInterrupted[] = "Enemy Trade Interrupted";
// GLOBAL: IMPERIALISM 0x0069476c
char g_szUiSeaOfSalamanders[] = "Sea of Satanic Salamanders";
// GLOBAL: IMPERIALISM 0x0069478c
char g_szUiEngageAllFloating[] = "Engage all floating objects";
// GLOBAL: IMPERIALISM 0x006947b0
char g_szUiForceCurrentlyLocated[] = "Force currently located in the";
// GLOBAL: IMPERIALISM 0x006947d8
char g_szUiTaskForceReport[] = "Task Force Report";
// GLOBAL: IMPERIALISM 0x006947f0
char g_szUiRegularsLabel[] = "Regulars";
// GLOBAL: IMPERIALISM 0x006947fc
char g_szUiSkirmishersLabel[] = "Skirmishers";
// GLOBAL: IMPERIALISM 0x0069480c
char g_szUiMinutemanLabel[] = "Minuteman";
// GLOBAL: IMPERIALISM 0x00694818
char g_szUiConstructionOptions[] = "Construction Options";
// GLOBAL: IMPERIALISM 0x00694834
char g_szUiEditTextLabel[] = "Edit Text";
// GLOBAL: IMPERIALISM 0x00694840
char g_szUiAdmiralBobMinnow[] = "Adm. Bob of the SS Minnow commanding";
// GLOBAL: IMPERIALISM 0x0069486c
char g_szUiCompositionLabel[] = "Composition";
// GLOBAL: IMPERIALISM 0x0069487c
char g_szUiPatrolTheWaters[] = "Patrol the waters\nof whereever";
// GLOBAL: IMPERIALISM 0x006948ac
char g_szUiOneHenTwoDucks[] = "One hen,\ntwo ducks, \nthree quacking geese.";
// GLOBAL: IMPERIALISM 0x006948e0
char g_szUiArmyReportTitle[] = "Army Report";
// GLOBAL: IMPERIALISM 0x006948f0
char g_szUiCivilianReportTitle[] = "Civilian Report";
// GLOBAL: IMPERIALISM 0x00694904
char g_szUiLossesHaxaco[] = "Losses\nHaxaco:  light\nOrdune:  heavy";
// GLOBAL: IMPERIALISM 0x00694930
char g_szUiOrderOfBattle[] = "Order of Battle follows";
// GLOBAL: IMPERIALISM 0x0069494c
char g_szUiHaxacoLegions[] = "Haxaco's Powerful Legions\nannhilate\nOrdune's Pathetic Armies";
// GLOBAL: IMPERIALISM 0x00694998
char g_szUiSkirmishReportTitle[] = "Skirmish Report";
// GLOBAL: IMPERIALISM 0x006949ac
char g_szUiPage14of14[] = "Page 14 of 14";

// University-screen (turn event 0x23fa) placeholder label strings.
// GLOBAL: IMPERIALISM 0x006943ac
char g_szUiPlaceholderOne[] = "1";
// GLOBAL: IMPERIALISM 0x006949c8
char g_szUiAvailableColon[] = "Available:";
// GLOBAL: IMPERIALISM 0x006949d8
char g_szUiCostColon[] = "Cost:";
// GLOBAL: IMPERIALISM 0x00694b20
char g_szUiUniversityTitle[] = "University";
// GLOBAL: IMPERIALISM 0x00694b30
char g_szUiThousandDollars[] = "$1,000";
// GLOBAL: IMPERIALISM 0x00694b38
char g_szUiLevel1[] = "Level\n1";
// GLOBAL: IMPERIALISM 0x006943cc
char g_szMcAppUiHeaderPath[] = "D:\\Ambit\\McAppUI.h";
// GLOBAL: IMPERIALISM 0x00696bc0
char g_szUGameWindowSourcePath[] = "D:\\Ambit\\Cross\\UGameWindow.cpp";
// GLOBAL: IMPERIALISM 0x00696728
char g_szUCountrySourcePath[] = "D:\\Ambit\\Cross\\UCountry.cpp";
// GLOBAL: IMPERIALISM 0x00696960
int g_diplomacyActionButtonTagTable[6] = {kControlTagInfo, kControlTagTrty, kControlTagGran,
                                          kControlTagTrad, kControlTagCoun, kControlTagOffr};
// GLOBAL: IMPERIALISM 0x00696978
extern "C" unsigned int g_aDiplomacyActionTopicTabTags[6] = {kControlTagInft, kControlTagTrtt,
                                                             kControlTagGrat, kControlTagTrat,
                                                             kControlTagCout, kControlTagOffr};
// GLOBAL: IMPERIALISM 0x00696990
short g_aDiplomacyRelationPaletteColorCodes[7] = {0x40, 0x40, 0x41, 0x42, 0x43, 0x40, 0x44};
// TInfoPanelView::Draw label-column coordinates, in the panel's parent coordinate space.
// GLOBAL: IMPERIALISM 0x006969b0
short g_infoPanelLabelXByRow[4] = {0x48, 0x48, 0x48, 0x48};
// GLOBAL: IMPERIALISM 0x006969c0
short g_infoPanelLabelYByRow[4] = {0x198, 0x1a9, 0x1ba, 0x1cb};
// GLOBAL: IMPERIALISM 0x006a143c
int g_McAppUiFlag_006A143C = 0;
// GLOBAL: IMPERIALISM 0x006a1484
int g_dibCompressAssertGate = 0;
// GLOBAL: IMPERIALISM 0x006a14e0
double g_gfxScale6A14E0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1528
short g_scaledShortConst_6A1528 = static_cast<short>(g_gfxScale6A14E0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1580
double g_gfxScale6A1580 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a15c8
short g_scaledShortConst_6A15C8 = static_cast<short>(g_gfxScale6A1580 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a12f8
double g_gfxCoordinateScale_6A12F8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1340
short g_scaledShortConst_6A1340 = static_cast<short>(g_gfxCoordinateScale_6A12F8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a13a8
double g_gfxCoordinateScale_6A13A8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1418
short g_scaledShortConst_6A1418 = static_cast<short>(g_gfxCoordinateScale_6A13A8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1638
double g_gfxCoordinateScale_6A1638 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1680
short g_scaledShortConst_6A1680 = static_cast<short>(g_gfxCoordinateScale_6A1638 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1690
double g_gfxCoordinateScale_6A1690 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a16d8
short g_scaledShortConst_6A16D8 = static_cast<short>(g_gfxCoordinateScale_6A1690 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1730
double g_gfxCoordinateScale_6A1730 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a177c
short g_scaledShortConst_6A177C = static_cast<short>(g_gfxCoordinateScale_6A1730 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a17e8
double g_gfxCoordinateScale_6A17E8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1830
short g_scaledShortConst_6A1830 = static_cast<short>(g_gfxCoordinateScale_6A17E8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a18f0
double g_gfxCoordinateScale_6A18F0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1938
short g_scaledShortConst_6A1938 = static_cast<short>(g_gfxCoordinateScale_6A18F0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1a30
double g_gfxCoordinateScale_6A1A30 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1ab8
short g_scaledShortConst_6A1AB8 = static_cast<short>(g_gfxCoordinateScale_6A1A30 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1bf0
double g_gfxCoordinateScale_6A1BF0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1c38
short g_scaledShortConst_6A1C38 = static_cast<short>(g_gfxCoordinateScale_6A1BF0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1cd8
double g_gfxCoordinateScale_6A1CD8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1d88
short g_scaledShortConst_6A1D88 = static_cast<short>(g_gfxCoordinateScale_6A1CD8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a21f8
double g_gfxCoordinateScale_6A21F8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2248
short g_scaledShortConst_6A2248 = static_cast<short>(g_gfxCoordinateScale_6A21F8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2268
double g_gfxCoordinateScale_6A2268 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a22d8
short g_scaledShortConst_6A22D8 = static_cast<short>(g_gfxCoordinateScale_6A2268 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2308
double g_gfxCoordinateScale_6A2308 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2350
short g_scaledShortConst_6A2350 = static_cast<short>(g_gfxCoordinateScale_6A2308 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2360
double g_gfxCoordinateScale_6A2360 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a23b0
short g_scaledShortConst_6A23B0 = static_cast<short>(g_gfxCoordinateScale_6A2360 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a23d0
double g_gfxCoordinateScale_6A23D0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2418
short g_scaledShortConst_6A2418 = static_cast<short>(g_gfxCoordinateScale_6A23D0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2428
double g_gfxCoordinateScale_6A2428 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2470
short g_scaledShortConst_6A2470 = static_cast<short>(g_gfxCoordinateScale_6A2428 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2488
double g_gfxCoordinateScale_6A2488 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a24d0
short g_scaledShortConst_6A24D0 = static_cast<short>(g_gfxCoordinateScale_6A2488 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2968
double g_gfxCoordinateScale_6A2968 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2ab8
short g_scaledShortConst_6A2AB8 = static_cast<short>(g_gfxCoordinateScale_6A2968 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2bf8
double g_gfxCoordinateScale_6A2BF8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2c60
short g_scaledShortConst_6A2C60 = static_cast<short>(g_gfxCoordinateScale_6A2BF8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2c98
double g_gfxCoordinateScale_6A2C98 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2d00
short g_scaledShortConst_6A2D00 = static_cast<short>(g_gfxCoordinateScale_6A2C98 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2d30
double g_gfxCoordinateScale_6A2D30 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2d80
short g_scaledShortConst_6A2D80 = static_cast<short>(g_gfxCoordinateScale_6A2D30 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2de0
double g_gfxCoordinateScale_6A2DE0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2e28
short g_scaledShortConst_6A2E28 = static_cast<short>(g_gfxCoordinateScale_6A2DE0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2e38
double g_gfxCoordinateScale_6A2E38 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2e80
short g_scaledShortConst_6A2E80 = static_cast<short>(g_gfxCoordinateScale_6A2E38 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2e90
double g_gfxCoordinateScale_6A2E90 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2ee8
short g_scaledShortConst_6A2EE8 = static_cast<short>(g_gfxCoordinateScale_6A2E90 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2f00
double g_gfxCoordinateScale_6A2F00 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2f48
short g_scaledShortConst_6A2F48 = static_cast<short>(g_gfxCoordinateScale_6A2F00 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2f58
double g_gfxCoordinateScale_6A2F58 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2fa0
short g_scaledShortConst_6A2FA0 = static_cast<short>(g_gfxCoordinateScale_6A2F58 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a2fb0
double g_gfxCoordinateScale_6A2FB0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3018
short g_scaledShortConst_6A3018 = static_cast<short>(g_gfxCoordinateScale_6A2FB0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3048
double g_gfxCoordinateScale_6A3048 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a30a0
short g_scaledShortConst_6A30A0 = static_cast<short>(g_gfxCoordinateScale_6A3048 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3118
double g_gfxCoordinateScale_6A3118 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3160
short g_scaledShortConst_6A3160 = static_cast<short>(g_gfxCoordinateScale_6A3118 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3170
double g_gfxCoordinateScale_6A3170 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a31b8
short g_scaledShortConst_6A31B8 = static_cast<short>(g_gfxCoordinateScale_6A3170 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a31d8
double g_gfxCoordinateScale_6A31D8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3220
short g_scaledShortConst_6A3220 = static_cast<short>(g_gfxCoordinateScale_6A31D8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3230
double g_gfxCoordinateScale_6A3230 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3278
short g_scaledShortConst_6A3278 = static_cast<short>(g_gfxCoordinateScale_6A3230 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3290
double g_gfxCoordinateScale_6A3290 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a32e0
short g_scaledShortConst_6A32E0 = static_cast<short>(g_gfxCoordinateScale_6A3290 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3488
double g_gfxCoordinateScale_6A3488 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a38f4
short g_scaledShortConst_6A38F4 = static_cast<short>(g_gfxCoordinateScale_6A3488 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3a08
double g_gfxCoordinateScale_6A3A08 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3a50
short g_scaledShortConst_6A3A50 = static_cast<short>(g_gfxCoordinateScale_6A3A08 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3a78
double g_gfxCoordinateScale_6A3A78 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3b80
short g_scaledShortConst_6A3B80 = static_cast<short>(g_gfxCoordinateScale_6A3A78 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3bf8
double g_gfxCoordinateScale_6A3BF8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3c64
short g_scaledShortConst_6A3C64 = static_cast<short>(g_gfxCoordinateScale_6A3BF8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3c88
double g_gfxCoordinateScale_6A3C88 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3cd0
short g_scaledShortConst_6A3CD0 = static_cast<short>(g_gfxCoordinateScale_6A3C88 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3ce8
double g_gfxCoordinateScale_6A3CE8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3d50
short g_scaledShortConst_6A3D50 = static_cast<short>(g_gfxCoordinateScale_6A3CE8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3d88
double g_gfxCoordinateScale_6A3D88 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3dd0
short g_scaledShortConst_6A3DD0 = static_cast<short>(g_gfxCoordinateScale_6A3D88 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3de8
double g_gfxCoordinateScale_6A3DE8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3eb8
short g_scaledShortConst_6A3EB8 = static_cast<short>(g_gfxCoordinateScale_6A3DE8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3f18
double g_gfxCoordinateScale_6A3F18 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3f60
short g_scaledShortConst_6A3F60 = static_cast<short>(g_gfxCoordinateScale_6A3F18 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3f70
double g_gfxCoordinateScale_6A3F70 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a3fb8
short g_scaledShortConst_6A3FB8 = static_cast<short>(g_gfxCoordinateScale_6A3F70 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a3fe0
double g_gfxCoordinateScale_6A3FE0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4028
short g_scaledShortConst_6A4028 = static_cast<short>(g_gfxCoordinateScale_6A3FE0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4038
double g_gfxCoordinateScale_6A4038 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4080
short g_scaledShortConst_6A4080 = static_cast<short>(g_gfxCoordinateScale_6A4038 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4098
double g_gfxCoordinateScale_6A4098 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a40e0
short g_scaledShortConst_6A40E0 = static_cast<short>(g_gfxCoordinateScale_6A4098 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a40f0
double g_gfxCoordinateScale_6A40F0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4138
short g_scaledShortConst_6A4138 = static_cast<short>(g_gfxCoordinateScale_6A40F0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4148
double g_gfxCoordinateScale_6A4148 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4190
short g_scaledShortConst_6A4190 = static_cast<short>(g_gfxCoordinateScale_6A4148 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a41b0
double g_gfxCoordinateScale_6A41B0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a41f8
short g_scaledShortConst_6A41F8 = static_cast<short>(g_gfxCoordinateScale_6A41B0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4208
double g_gfxCoordinateScale_6A4208 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4260
short g_scaledShortConst_6A4260 = static_cast<short>(g_gfxCoordinateScale_6A4208 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a42e0
double g_gfxCoordinateScale_6A42E0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a43bc
short g_scaledShortConst_6A43BC = static_cast<short>(g_gfxCoordinateScale_6A42E0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4440
double g_gfxCoordinateScale_6A4440 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4488
short g_scaledShortConst_6A4488 = static_cast<short>(g_gfxCoordinateScale_6A4440 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a44d0
double g_gfxCoordinateScale_6A44D0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4518
short g_scaledShortConst_6A4518 = static_cast<short>(g_gfxCoordinateScale_6A44D0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4538
double g_gfxCoordinateScale_6A4538 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4580
short g_scaledShortConst_6A4580 = static_cast<short>(g_gfxCoordinateScale_6A4538 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a4630
double g_gfxCoordinateScale_6A4630 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a46a0
short g_scaledShortConst_6A46A0 = static_cast<short>(g_gfxCoordinateScale_6A4630 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a46d8
double g_gfxCoordinateScale_6A46D8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a4748
short g_scaledShortConst_6A4748 = static_cast<short>(g_gfxCoordinateScale_6A46D8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5438
double g_gfxCoordinateScale_6A5438 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a54a8
short g_scaledShortConst_6A54A8 = static_cast<short>(g_gfxCoordinateScale_6A5438 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5760
double g_gfxCoordinateScale_6A5760 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a57a8
short g_scaledShortConst_6A57A8 = static_cast<short>(g_gfxCoordinateScale_6A5760 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a57b8
double g_gfxCoordinateScale_6A57B8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5800
short g_scaledShortConst_6A5800 = static_cast<short>(g_gfxCoordinateScale_6A57B8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5810
double g_gfxCoordinateScale_6A5810 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5858
short g_scaledShortConst_6A5858 = static_cast<short>(g_gfxCoordinateScale_6A5810 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5868
double g_gfxCoordinateScale_6A5868 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a58b0
short g_scaledShortConst_6A58B0 = static_cast<short>(g_gfxCoordinateScale_6A5868 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a58c0
double g_gfxCoordinateScale_6A58C0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5908
short g_scaledShortConst_6A5908 = static_cast<short>(g_gfxCoordinateScale_6A58C0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5920
double g_gfxCoordinateScale_6A5920 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5968
short g_scaledShortConst_6A5968 = static_cast<short>(g_gfxCoordinateScale_6A5920 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5978
double g_gfxCoordinateScale_6A5978 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a59c0
short g_scaledShortConst_6A59C0 = static_cast<short>(g_gfxCoordinateScale_6A5978 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a59d0
double g_gfxCoordinateScale_6A59D0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5a20
short g_scaledShortConst_6A5A20 = static_cast<short>(g_gfxCoordinateScale_6A59D0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5a48
double g_gfxCoordinateScale_6A5A48 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5a90
short g_scaledShortConst_6A5A90 = static_cast<short>(g_gfxCoordinateScale_6A5A48 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5aa0
double g_gfxCoordinateScale_6A5AA0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5ae8
short g_scaledShortConst_6A5AE8 = static_cast<short>(g_gfxCoordinateScale_6A5AA0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5b48
double g_gfxCoordinateScale_6A5B48 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5ba8
short g_scaledShortConst_6A5BA8 = static_cast<short>(g_gfxCoordinateScale_6A5B48 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5bd0
double g_gfxCoordinateScale_6A5BD0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5c18
short g_scaledShortConst_6A5C18 = static_cast<short>(g_gfxCoordinateScale_6A5BD0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5c28
double g_gfxCoordinateScale_6A5C28 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5c70
short g_scaledShortConst_6A5C70 = static_cast<short>(g_gfxCoordinateScale_6A5C28 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5c80
double g_gfxCoordinateScale_6A5C80 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5cf0
short g_scaledShortConst_6A5CF0 = static_cast<short>(g_gfxCoordinateScale_6A5C80 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5de0
double g_gfxCoordinateScale_6A5DE0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5e28
short g_scaledShortConst_6A5E28 = static_cast<short>(g_gfxCoordinateScale_6A5DE0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a5ec8
double g_gfxCoordinateScale_6A5EC8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a5f3c
short g_scaledShortConst_6A5F3C = static_cast<short>(g_gfxCoordinateScale_6A5EC8 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a6070
double g_gfxCoordinateScale_6A6070 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a60b8
short g_scaledShortConst_6A60B8 = static_cast<short>(g_gfxCoordinateScale_6A6070 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x00698ab8
char g_szSetupScreensSourcePath[] = "D:\\Ambit\\Cross\\USetupScreens.cpp";
// GLOBAL: IMPERIALISM 0x006a4264
int g_SetupScreensAssertFlag = 0;
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
// GLOBAL: IMPERIALISM 0x006a1b5c
int g_McAppUiFlag_006A1B5C = 0;

// GLOBAL: IMPERIALISM 0x0064b8f0
int g_defaultPenWidth = 1;
// GLOBAL: IMPERIALISM 0x0064b8f4
int g_defaultPenHeight = 1;
// GLOBAL: IMPERIALISM 0x0064b8f8
extern const short g_Reset_Quick_Draw_WordState = 0;
// GLOBAL: IMPERIALISM 0x006a1d10
short g_Reset_Quick_Draw_State = 0;
// GLOBAL: IMPERIALISM 0x006a1d08
int g_nQuickDrawPenHorizontalSize = 0;
// GLOBAL: IMPERIALISM 0x006a1d0c
int g_nQuickDrawPenVerticalSize = 0;
// GLOBAL: IMPERIALISM 0x006a1db4
int g_bQuickDrawStrokePairDirty = 0;
// GLOBAL: IMPERIALISM 0x006a1da8
CRgn* g_pGlobalClipRegionHandleObject = NULL;
// GLOBAL: IMPERIALISM 0x006950fc
COLORREF g_QuickDrawForegroundColor = PALETTEINDEX(0xff);
// GLOBAL: IMPERIALISM 0x00695100
COLORREF g_QuickDrawBackgroundColor = PALETTEINDEX(0);
// GLOBAL: IMPERIALISM 0x006a1ce8
CFont* g_pQuickDrawCachedUiFont = 0;
// GLOBAL: IMPERIALISM 0x006a1cec
TextStyle g_QuickDrawCachedFontPreset = {0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a1cf6
bool g_bQuickDrawCachedFontDirty = false;

// GLOBAL: IMPERIALISM 0x006a1d48
CFont* g_pQuickDrawCachedMeasureFont = 0;
// GLOBAL: IMPERIALISM 0x006a1d4c
TextStyle g_QuickDrawMeasureFontPreset = {0, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x006a1d56
bool g_bQuickDrawMeasureFontDirty = false;
// GLOBAL: IMPERIALISM 0x006a1d80
int g_nQuickDrawOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a1d84
int g_nQuickDrawOriginY = 0;
// GLOBAL: IMPERIALISM 0x006a1d00
int g_nQuickDrawResolvedTextOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a1d04
int g_nQuickDrawResolvedTextOriginY = 0;
// GLOBAL: IMPERIALISM 0x006a5458
int g_nUiFrameClipOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a545c
int g_nUiFrameClipOriginY = 0;
// GLOBAL: IMPERIALISM 0x006a1ca0
TBitmapSurfaceContextDescriptor g_defaultQuickDrawSurfaceSentinel;
// GLOBAL: IMPERIALISM 0x006950f8
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead = &g_defaultQuickDrawSurfaceSentinel;
// GLOBAL: IMPERIALISM 0x006a1d60
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a30a8
TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a3450
TQuickDrawSurfaceContext* g_pCitySiteCachedPrimaryRenderSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a3454
short g_MapTileCacheMissCount6A3454;
// GLOBAL: IMPERIALISM 0x006a4194
CDib* g_pColorKeyCompositeDib = 0;

// GLOBAL: IMPERIALISM 0x00697310
short g_aStrategicMapNeighborHighlightTiles[6] = {-1, -1, -1, -1, -1, -1};
// GLOBAL: IMPERIALISM 0x00697320
short g_aCitySiteNeighborHighlightTiles[6] = {-1, -1, -1, -1, -1, -1};

// GLOBAL: IMPERIALISM 0x006a3370
CPoint g_MapInteractionPreviewPoint(0, 0);
// GLOBAL: IMPERIALISM 0x006a33b4
int g_MapInteractionPreviewRowParity = 0;
// GLOBAL: IMPERIALISM 0x006a33b8
int g_MapInteractionPreviewColumnParity = 0;
// GLOBAL: IMPERIALISM 0x006a1da0
CDC* g_pQuickDrawMemoryDc = NULL;
// GLOBAL: IMPERIALISM 0x006a1dbc
HGDIOBJ g_hQuickDrawSavedBitmap = NULL;
// GLOBAL: IMPERIALISM 0x006a1db0
int g_nActiveQuickDrawSurfaceFlags = 0;
// RefreshRgnBoundingBox asserts when this compatibility gate is zero.
// GLOBAL: IMPERIALISM 0x006a1dc4
int g_QuickDrawRegionBoundsAssertGate = 0;
// GLOBAL: IMPERIALISM 0x006a1dc8
int g_QuickDrawSetCursorAssertGate = 0;
// GLOBAL: IMPERIALISM 0x006a1dcc
int g_QuickDrawGetCursorAssertGate = 0;
// EqualRgn reports its unsupported QuickDraw compatibility assertion when zero.
// GLOBAL: IMPERIALISM 0x006a1dd0
int g_QuickDrawEqualRgnAssertGate = 0;
// Stroke-state compatibility gate read only by the dead out-of-line copy at 0x495370.
// GLOBAL: IMPERIALISM 0x006a1db8
int g_QuickDrawStateAssertGate = 0;

// Overlay clip cache parameters
// GLOBAL: IMPERIALISM 0x006a4450
int g_nOverlayClipCacheParamX = 0;
// GLOBAL: IMPERIALISM 0x006a4454
int g_nOverlayClipCacheParamY = 0;

// GLOBAL: IMPERIALISM 0x00696108
const int g_pTradeSummarySelectionMap[23] = {
    kManifestTagCott, kManifestTagWool,  kManifestTagTimb, kManifestTagCoal, kManifestTagIron,
    kManifestTagHors, kManifestTagOilSp, kSummaryTagFood,  kManifestTagFabr, kManifestTagLumb,
    kManifestTagPape, kManifestTagStee,  kManifestTagFuel, kControlTagClot,  kControlTagFurn,
    kControlTagHard,  kManifestTagArma,  kControlTagGrai,  kControlTagProd,  kControlTagFish,
    kManifestTagLive, kManifestTagGems,  kManifestTagGold,
};

// Trade sell propagation tags.
const int kTradeSellPropagationTags[17] = {
    kControlTagRs0Sp, kControlTagRs1Sp, kControlTagRs2Sp, kControlTagRs3Sp, kControlTagRs4Sp,
    kControlTagRs5Sp, kControlTagRs6Sp, kControlTagMa0Sp, kControlTagMa1Sp, kControlTagMa2Sp,
    kControlTagMa3Sp, kControlTagMa4Sp, kControlTagMa5Sp, kControlTagGd0Sp, kControlTagGd1Sp,
    kControlTagGd2Sp, kControlTagGd3Sp,
};

// GLOBAL: IMPERIALISM 0x0066b1a0
const int g_tradeBidNationMetricControlTags[24] = {kControlTagRs0Sp,
                                                   kControlTagRs1Sp,
                                                   kControlTagRs2Sp,
                                                   kControlTagRs3Sp,
                                                   kControlTagRs4Sp,
                                                   kControlTagRs5Sp,
                                                   kControlTagRs6Sp,
                                                   kControlTagMa0Sp,
                                                   kControlTagMa1Sp,
                                                   kControlTagMa2Sp,
                                                   kControlTagMa3Sp,
                                                   kControlTagMa4Sp,
                                                   kControlTagMa5Sp,
                                                   kControlTagGd0Sp,
                                                   kControlTagGd1Sp,
                                                   kControlTagGd2Sp,
                                                   kControlTagGd3Sp,
                                                   0,
                                                   -1,
                                                   -1,
                                                   -1,
                                                   0,
                                                   1,
                                                   -1};

// Treaty-dialog panel and cell tags, stored as packed four-character control IDs.
// GLOBAL: IMPERIALISM 0x0066b100
const unsigned int g_majorTreatyPanelTags[kMajorNationCount] = {
    kManifestTagGP0Sp, kManifestTagGP1Sp, kManifestTagGP2Sp, kManifestTagGP3Sp,
    kManifestTagGP4Sp, kManifestTagGP5Sp, kManifestTagGP6Sp};
// GLOBAL: IMPERIALISM 0x0066b13c
const unsigned int g_minorTreatyPanelTags[kMinorNationCount] = {
    kManifestTagM7SpSp, kManifestTagM8SpSp, kManifestTagM9SpSp, kManifestTagM10Sp,
    kManifestTagM11Sp,  kManifestTagM12Sp,  kManifestTagM13Sp,  kManifestTagM14Sp,
    kManifestTagM15Sp,  kManifestTagM16Sp,  kManifestTagM17Sp,  kManifestTagM18Sp,
    kManifestTagM19Sp,  kManifestTagM20Sp,  kManifestTagM21Sp,  kManifestTagM22Sp};
// GLOBAL: IMPERIALISM 0x0066b180
const unsigned int g_majorTreatyCellTags[kMajorNationCount] = {
    kManifestTagRGP0, kManifestTagRGP1, kManifestTagRGP2, kManifestTagRGP3,
    kManifestTagRGP4, kManifestTagRGP5, kManifestTagRGP6};

// Industry action cost weight tables
// GLOBAL: IMPERIALISM 0x00650758
float g_AiDevelopmentResourceBudgetScale = 1000.0f;
// GLOBAL: IMPERIALISM 0x0064f488
extern const float g_PopulationGrowthRateUnder10 = 1.2f;
// GLOBAL: IMPERIALISM 0x0064f48c
extern const float g_PopulationGrowthRateUnder15 = 1.03f;
// GLOBAL: IMPERIALISM 0x0064f490
extern const float g_PopulationGrowthRateUnder20 = 1.02f;
// GLOBAL: IMPERIALISM 0x0064f494
extern const float g_PopulationGrowthRateUnder30 = 1.015f;
// GLOBAL: IMPERIALISM 0x0064f498
extern const float g_PopulationGrowthRateUnder40 = 1.012f;
// GLOBAL: IMPERIALISM 0x0064f49c
extern const float g_PopulationGrowthRateUnder60 = 1.011f;
// GLOBAL: IMPERIALISM 0x0064f4a0
extern const float g_PopulationGrowthRateUnder80 = 1.01f;
// GLOBAL: IMPERIALISM 0x0064f4a4
extern const float g_PopulationGrowthRateUnder400 = 1.005f;
// GLOBAL: IMPERIALISM 0x0064f4a8
extern const double g_PopulationGrowthPenaltyPerRetry = -0.001;
// GLOBAL: IMPERIALISM 0x0064f4b0
extern const double g_PopulationGrowthMaximumRetryPenalty = -0.02;
// GLOBAL: IMPERIALISM 0x0064f4b8
extern const float g_PopulationGrowthRateAtOrAbove400 = 1.0f;
// GLOBAL: IMPERIALISM 0x00695b48
short g_cityPredictedNeedResetResourceIds[3] = {15, 13, 14};
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

// Per-city-action metric/cost profiles used by the AI development planner.
// GLOBAL: IMPERIALISM 0x00695cd2
AiCityActionCostProfile g_aiCityActionCostProfiles[30] = {
    {-1, 0, -1, 0, 0, 1, 1},      {16, 1, -1, 0, 200, 1, 2},   {16, 1, -1, 0, 500, 1, 3},
    {16, 1, -1, 0, 1000, 2, 4},   {16, 1, 5, 1, 100, 1, 5},    {16, 1, 5, 1, 500, 2, 6},
    {16, 2, 5, 1, 1000, 2, 7},    {16, 2, -1, 0, 1000, 2, 8},  {-1, 0, -1, 0, 0, 1, 9},
    {16, 2, -1, 0, 3000, 1, 10},  {16, 2, -1, 0, 3000, 1, 11}, {16, 2, -1, 0, 4000, 2, 12},
    {16, 2, 5, 1, 2000, 1, 13},   {16, 2, 5, 1, 3500, 2, 14},  {16, 4, 5, 1, 5000, 2, 15},
    {16, 4, -1, 0, 5000, 2, 16},  {-1, 0, -1, 0, 0, 1, 17},    {16, 4, -1, 0, 5000, 2, 18},
    {16, 4, -1, 0, 5000, 2, 19},  {16, 4, -1, 0, 7000, 2, 20}, {16, 4, 12, 4, 5000, 2, 21},
    {16, 10, 12, 4, 9000, 2, 22}, {16, 6, 12, 4, 5000, 2, 23}, {16, 8, -1, 0, 9000, 2, 24},
    {16, 2, -1, 0, 5000, 4, 25},  {16, 2, -1, 0, 7000, 4, 26}, {16, 3, -1, 0, 9000, 4, 27},
    {-1, 0, -1, 0, 0, 4, 28},     {-1, 0, -1, 0, 0, 4, 29},    {-1, 0, -1, 0, 0, 4, 0},
};

// GLOBAL: IMPERIALISM 0x006967d4
short g_cachedAiCityActionNationSlot = -1;
// GLOBAL: IMPERIALISM 0x006967d8
short g_cachedAiCityActionTurnTick = -1;
// GLOBAL: IMPERIALISM 0x006a2ea0
float g_cachedAiCityActionContextBias[3] = {0.0f, 0.0f, 0.0f};

// GLOBAL: IMPERIALISM 0x00696178
short g_anCityBuildingSlotOrder[16] = {12, 13, 7, 10, 14, 15, 9, 6, 11, 2, 3, 8, 0, 1, 4, 5};
// GLOBAL: IMPERIALISM 0x00696198
short g_anCityBuildingSlotCoords[32] = {200, 235, 340, 300, 281, 184, 340, 266, 87,  286, 230,
                                        310, 340, 139, 240, 35,  50,  220, 50,  107, 50,  35,
                                        340, 139, 82,  35,  300, 35,  340, 44,  150, 95};
// GLOBAL: IMPERIALISM 0x006961d8
short g_nCityBuildingSlotYOffsetIndex = 1;
// GLOBAL: IMPERIALISM 0x006961dc
short g_nCityBuildingDrawXOffsetIndex = 1;
// GLOBAL: IMPERIALISM 0x0064faa8
char* g_pCityBuildingHoverEmptyText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0064fad0
short g_awCityBuildingActionResourceIds[72] = {
    12, 0,  0,  12, 14, 0,  11, 0,  0, 12, 0,  0, 12, 12, 0, 12, 12, 0,  24, 24, 0, 24, 24, 0,
    9,  21, 11, 25, 9,  0,  12, 24, 0, 12, 26, 0, 12, 23, 0, 24, 25, 25, 19, 19, 0, 12, 11, 0,
    13, 0,  0,  12, 13, 11, 7,  0,  0, 0,  0,  0, 0,  0,  0, 13, 0,  0,  0,  0,  0, 0,  0,  0};
// Runtime column-selector indices into g_anCityBuildingSlotCoords pairs (BSS, 0 at load).
// GLOBAL: IMPERIALISM 0x006a2abc
short g_nCityBuildingSlotXOffsetIndex = 0;
// GLOBAL: IMPERIALISM 0x006a2ac0
short g_nCityBuildingDrawYOffsetIndex = 0;

// GLOBAL: IMPERIALISM 0x006a2980
CRect g_cityBuildingHoverFallbackRect;
// GLOBAL: IMPERIALISM 0x006a2998
CRect g_aCityBuildingHoverSelectionRects[16] = {
    CRect(g_anCityBuildingSlotCoords[0], g_anCityBuildingSlotCoords[1],
          g_anCityBuildingSlotCoords[0] + 10, g_anCityBuildingSlotCoords[1] + 10),
    CRect(g_anCityBuildingSlotCoords[2], g_anCityBuildingSlotCoords[3],
          g_anCityBuildingSlotCoords[2] + 10, g_anCityBuildingSlotCoords[3] + 10),
    CRect(g_anCityBuildingSlotCoords[4], g_anCityBuildingSlotCoords[5],
          g_anCityBuildingSlotCoords[4] + 10, g_anCityBuildingSlotCoords[5] + 10),
    CRect(g_anCityBuildingSlotCoords[6], g_anCityBuildingSlotCoords[7],
          g_anCityBuildingSlotCoords[6] + 10, g_anCityBuildingSlotCoords[7] + 10),
    CRect(g_anCityBuildingSlotCoords[8], g_anCityBuildingSlotCoords[9],
          g_anCityBuildingSlotCoords[8] + 10, g_anCityBuildingSlotCoords[9] + 10),
    CRect(g_anCityBuildingSlotCoords[10], g_anCityBuildingSlotCoords[11],
          g_anCityBuildingSlotCoords[10] + 10, g_anCityBuildingSlotCoords[11] + 10),
    CRect(g_anCityBuildingSlotCoords[12], g_anCityBuildingSlotCoords[13],
          g_anCityBuildingSlotCoords[12] + 10, g_anCityBuildingSlotCoords[13] + 10),
    CRect(g_anCityBuildingSlotCoords[14], g_anCityBuildingSlotCoords[15],
          g_anCityBuildingSlotCoords[14] + 10, g_anCityBuildingSlotCoords[15] + 10),
    CRect(g_anCityBuildingSlotCoords[16], g_anCityBuildingSlotCoords[17],
          g_anCityBuildingSlotCoords[16] + 10, g_anCityBuildingSlotCoords[17] + 10),
    CRect(g_anCityBuildingSlotCoords[18], g_anCityBuildingSlotCoords[19],
          g_anCityBuildingSlotCoords[18] + 10, g_anCityBuildingSlotCoords[19] + 10),
    CRect(g_anCityBuildingSlotCoords[20], g_anCityBuildingSlotCoords[21],
          g_anCityBuildingSlotCoords[22] + 10, g_anCityBuildingSlotCoords[23] + 10),
    CRect(g_anCityBuildingSlotCoords[24], g_anCityBuildingSlotCoords[25],
          g_anCityBuildingSlotCoords[26] + 10, g_anCityBuildingSlotCoords[27] + 10),
    CRect(g_anCityBuildingSlotCoords[26], g_anCityBuildingSlotCoords[27],
          g_anCityBuildingSlotCoords[26] + 10, g_anCityBuildingSlotCoords[27] + 10),
    CRect(g_anCityBuildingSlotCoords[28], g_anCityBuildingSlotCoords[29],
          g_anCityBuildingSlotCoords[28] + 10, g_anCityBuildingSlotCoords[29] + 10),
    CRect(g_anCityBuildingSlotCoords[30], g_anCityBuildingSlotCoords[31],
          g_anCityBuildingSlotCoords[30] + 10, g_anCityBuildingSlotCoords[31] + 10),
    CRect(g_anCityBuildingSlotCoords[32], g_anCityBuildingSlotCoords[33],
          g_anCityBuildingSlotCoords[32] + 10, g_anCityBuildingSlotCoords[33] + 10)};

// GLOBAL: IMPERIALISM 0x006a24e8
CRect g_aCityBuildingLayoutRects[72] = {CRect(0x110, 0xfc, 0x11f, 0x10a),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x110, 0xfc, 0x11f, 0x10a),
                                        CRect(0xd3, 0xd1, 0xe4, 0xe0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0xd3, 0xd4, 0x111, 0x10f),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x1b4, 0x15a, 0x1c3, 0x169),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x1a9, 0x14c, 0x1c3, 0x169),
                                        CRect(0x16b, 0x116, 0x187, 0x131),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x1a9, 0x14c, 0x1c3, 0x169),
                                        CRect(0x173, 0x123, 0x199, 0x14b),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x16c, 0xb7, 0x192, 0xeb),
                                        CRect(0x185, 0xed, 0x1ce, 0x10d),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x155, 0xb6, 0x192, 0xf7),
                                        CRect(0x16f, 0xed, 0x1cd, 0x11b),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x158, 0xa1, 0x166, 0xbc),
                                        CRect(0x171, 0x107, 0x179, 0x10f),
                                        CRect(0x12e, 0xef, 0x13f, 0xfa),
                                        CRect(0x1d8, 0x11a, 0x1f3, 0x14e),
                                        CRect(0x1ba, 0x13d, 0x1d0, 0x146),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x1df, 0x124, 0x1f2, 0x14e),
                                        CRect(0x1c6, 0xfa, 0x1e3, 0x115),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x1da, 0xd5, 0x21a, 0x113),
                                        CRect(0x1bb, 0x121, 0x208, 0x14c),
                                        CRect(0, 0, 0, 0),
                                        CRect(0xb3, 0x144, 0xc3, 0x156),
                                        CRect(0xb4, 0x15e, 0xd2, 0x173),
                                        CRect(0, 0, 0, 0),
                                        CRect(0x8d, 0x124, 0xa9, 0x141),
                                        CRect(0xc2, 0x157, 0xda, 0x169),
                                        CRect(121, 325, 160, 338),
                                        CRect(185, 345, 224, 381),
                                        CRect(94, 326, 146, 368),
                                        CRect(0, 0, 0, 0),
                                        CRect(284, 374, 299, 388),
                                        CRect(273, 402, 322, 439),
                                        CRect(0, 0, 0, 0),
                                        CRect(303, 328, 327, 351),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(273, 327, 294, 348),
                                        CRect(304, 324, 328, 347),
                                        CRect(340, 362, 360, 381),
                                        CRect(441, 152, 463, 170),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(464, 130, 488, 153),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0),
                                        CRect(0, 0, 0, 0)};

// GLOBAL: IMPERIALISM 0x006a1da4
HRGN g_hOpenRgnAccumulator = NULL;

// GLOBAL: IMPERIALISM 0x006a24d4
bool g_Sanitize_City_Counter_Value = false;
// GLOBAL: IMPERIALISM 0x6a134c
TResourceMgr* g_pResourceMgr = NULL;
// GLOBAL: IMPERIALISM 0x00694150
LPCSTR g_apFontFiles[] = {"data\\WeBeBd__.ttf", "data\\Antqua.ttf", "data\\Antqua.ttf",
                          "data\\AntquaB.ttf", NULL};
// GLOBAL: IMPERIALISM 0x006a1890
int g_nDibOrientationFlag = 0;
// GLOBAL: IMPERIALISM 0x0069b89c
int g_nAuxOutputDeviceIndex = -1;
// GLOBAL: IMPERIALISM 0x6a1d9c
CDC* g_pScopedMapQuickDrawDcHandleObject = NULL;
// GLOBAL: IMPERIALISM 0x6a1dac
void* g_pScopedMapQuickDrawViewContext = 0;
// GLOBAL: IMPERIALISM 0x6a1c98
RgnHandle g_pTemporaryRegionCache = 0;

// GLOBAL: IMPERIALISM 0x006a2018
BOOL g_cachedShowSplashFlag = FALSE;

} // extern "C"

// Active root of the in-progress UI resource tree and the entry currently being registered.
// GLOBAL: IMPERIALISM 0x006a141c
TView* g_pUiResourceHead = NULL;
// GLOBAL: IMPERIALISM 0x006a1420
TView* g_pUiResourceContext = NULL;

// FUNCTION: IMPERIALISM 0x00489a50
int SetGlobalUiInvalidationFlagAndReturnPrevious(int newValue) {
  int previous = g_McAppUiActiveFlag;
  g_McAppUiActiveFlag = newValue;
  return previous;
}

// FUNCTION: IMPERIALISM 0x00489a70
int GetMcAppUiActiveFlag() {
  return g_McAppUiActiveFlag;
}

// FUNCTION: IMPERIALISM 0x00489a90
int ClearGlobalUiInvalidationFlagAndReturnPrevious() {
  int previous = g_McAppUiActiveFlag;
  g_McAppUiActiveFlag = 0;
  return previous;
}

// Source-path string for CMcWindow's McWindow.cpp one-shot debug asserts.
// GLOBAL: IMPERIALISM 0x006950d8
char g_szMcWindowSourcePath[] = "D:\\Ambit\\McWindow.cpp";

// GLOBAL: IMPERIALISM 0x006a1c74
int g_nMcWindowStateMsgAssertGate = 0;

// Source-path string for the DiplomacyDialogs.cpp resource-A4 dialog assert.
// GLOBAL: IMPERIALISM 0x00694cc0
extern "C" const char g_szDiplomacyDialogsSourcePath[] = "D:\\Ambit\\DiplomacyDialogs.cpp";

// Source-path string for CIncludeView's IncludeView.cpp one-shot debug asserts.
// GLOBAL: IMPERIALISM 0x00694d10
char g_szIncludeViewSourcePath[] = "D:\\Ambit\\IncludeView.cpp";

// GLOBAL: IMPERIALISM 0x006a17b0
int g_nIncludeViewAssertGate = 0;

// GLOBAL: IMPERIALISM 0x006a17b4
int g_nIncludeViewQueueAssertGate = 0;

// One-shot assert gate for starting a mouse-capture track without a live UI context.
// GLOBAL: IMPERIALISM 0x006a17b8
int g_nIncludeViewCaptureAssertGate = 0;

// GLOBAL: IMPERIALISM 0x006a17bc
int g_nIncludeViewReinitAssertGate = 0;

// GLOBAL: IMPERIALISM 0x006a17c0
int g_nIncludeViewReinitThreadOnceGate = 0;

// GLOBAL: IMPERIALISM 0x00694d40
char g_szAmbitCadreEgoutClassName[] = "AmbitCadreEgout";

// GLOBAL: IMPERIALISM 0x006a1834
int g_AmbitCadreEgoutWndClassAtom = 0;

// GLOBAL: IMPERIALISM 0x006a2480
int g_nMcAppUiAssertGate = 0;

// GLOBAL: IMPERIALISM 0x006a17c4
int g_nIncludeViewPointerAssertGate = 0;

extern "C" {

// GLOBAL: IMPERIALISM 0x006548e0
extern const float g_DefenseMinisterWeightZero = 0.0f;
// GLOBAL: IMPERIALISM 0x006548e8
extern const double g_MinisterWeightHalf = 0.5;
// GLOBAL: IMPERIALISM 0x006548f0
extern const double g_MinisterWeightOne = 1.0;
// GLOBAL: IMPERIALISM 0x006548f8
extern const double g_BismarckWeightHigh = 0.9;
// GLOBAL: IMPERIALISM 0x00654900
extern const double g_BismarckWeightLow = 0.6;
// GLOBAL: IMPERIALISM 0x00654908
extern const float g_DefenderMinisterWeight = 0.75f;
// GLOBAL: IMPERIALISM 0x00654910
extern const double g_BullyWeightLow = 0.7;
// GLOBAL: IMPERIALISM 0x00654918
extern const double g_BullyWeightHigh = 0.8;

// GLOBAL: IMPERIALISM 0x006545c8
extern const double g_AiPressureUnsetSentinel = -1.0;
// GLOBAL: IMPERIALISM 0x006545d4
extern const float g_UnreferencedConstant = -1.0f;
// GLOBAL: IMPERIALISM 0x006545e0
extern const float g_AiPressureRatioCap = 1.0f;
// GLOBAL: IMPERIALISM 0x006545e8
extern const double g_AiPressureMidpointScale = 0.5;
// 0.0 (double) threshold used by the same function's score-positivity checks.
// GLOBAL: IMPERIALISM 0x006545f0
extern const double g_MissionScoreZeroThreshold = 0.0;
// GLOBAL: IMPERIALISM 0x006545f8
extern const double g_MissionEligibilityRatioMargin = 1.1;

// GLOBAL: IMPERIALISM 0x006543e8
extern const float g_AiPressurePeerScale = 1.1f;

// GLOBAL: IMPERIALISM 0x00658780
float g_TileHeatmapNeighborDiffusionFactor = 0.2f;

// GLOBAL: IMPERIALISM 0x006a3410
double g_MapPreviewScaleX6A3410;
// GLOBAL: IMPERIALISM 0x006a33d0
double g_MapPreviewScaleY6A33D0;
// GLOBAL: IMPERIALISM 0x006a3448
short g_MapPreviewVerticalOffset6A3448;
// GLOBAL: IMPERIALISM 0x006a3360
extern double g_mapCellRowScale;
// GLOBAL: IMPERIALISM 0x006a3388
extern double g_mapCellColumnScale;
// GLOBAL: IMPERIALISM 0x006a32f8
extern double g_mapProjectionColumnScale;
// GLOBAL: IMPERIALISM 0x006a3320
extern double g_mapProjectionRowScale;
// GLOBAL: IMPERIALISM 0x006a3348
extern short g_mapProjectionSeamColumn;

} // extern "C"

// GLOBAL: IMPERIALISM 0x006a1cf8
CPoint g_defaultPoint_006A1CF8(0, 0);
// GLOBAL: IMPERIALISM 0x006a1d78
CPoint g_defaultPoint_006A1D78(0, 0);
// GLOBAL: IMPERIALISM 0x006a1d30
CRect g_defaultRect_006A1D30(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1d68
CRect g_defaultRect_006A1D68(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1ce0
CRGBColor g_defaultRgbColor_006A1CE0;
// GLOBAL: IMPERIALISM 0x006a1e20
CPoint g_defaultPoint_006A1E20(0, 0);
// GLOBAL: IMPERIALISM 0x006a1e48
CPoint g_defaultPoint_006A1E48(0, 0);
// GLOBAL: IMPERIALISM 0x006a1e28
CRect g_defaultRect_006A1E28(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1e38
CRect g_defaultRect_006A1E38(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1e18
CRGBColor g_defaultRgbColor_006A1E18;
// GLOBAL: IMPERIALISM 0x006a1e70
CPoint g_defaultPoint_006A1E70(0, 0);
// GLOBAL: IMPERIALISM 0x006a1f38
CPoint g_defaultPoint_006A1F38(0, 0);
// GLOBAL: IMPERIALISM 0x006a1f18
CRect g_defaultRect_006A1F18(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1f28
CRect g_defaultRect_006A1F28(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1e68
CRGBColor g_defaultRgbColor_006A1E68;
// GLOBAL: IMPERIALISM 0x006a1f78
CPoint g_defaultPoint_006A1F78(0, 0);
// GLOBAL: IMPERIALISM 0x006a1fa8
CPoint g_defaultPoint_006A1FA8(0, 0);
// GLOBAL: IMPERIALISM 0x006a1f88
CRect g_defaultRect_006A1F88(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1f98
CRect g_defaultRect_006A1F98(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1f70
CRGBColor g_defaultRgbColor_006A1F70;
// GLOBAL: IMPERIALISM 0x006a1fe8
double g_ScaleDefault6A1FE8 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a1fc0
double g_ScaleDefault6A1FC0 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2008
short g_scaledDefaultWidth = static_cast<short>(g_ScaleDefault6A1FC0 * 512.0 + 1.0);
// GLOBAL: IMPERIALISM 0x006a1fd0
CPoint g_defaultPoint_006A1FD0(0, 0);
// GLOBAL: IMPERIALISM 0x006a2000
CPoint g_defaultPoint_006A2000(0, 0);
// GLOBAL: IMPERIALISM 0x006a1fd8
CRect g_defaultRect_006A1FD8(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1ff0
CRect g_defaultRect_006A1FF0(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a1fc8
CRGBColor g_defaultRgbColor_006A1FC8;
// GLOBAL: IMPERIALISM 0x006a2020
CPoint g_defaultPoint_006A2020(0, 0);

// GLOBAL: IMPERIALISM 0x006a2048
CPoint g_defaultPoint_006A2048(0, 0);
// GLOBAL: IMPERIALISM 0x006a2028
CRect g_defaultRect_006A2028(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a2038
CRect g_defaultRect_006A2038(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a201c
CRGBColor g_defaultRgbColor_006A201C;

// GLOBAL: IMPERIALISM 0x006a2070
CPoint g_defaultPoint_006A2070(0, 0);
// GLOBAL: IMPERIALISM 0x006a2098
CPoint g_defaultPoint_006A2098(0, 0);
// GLOBAL: IMPERIALISM 0x006a2078
CRect g_defaultRect_006A2078(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a2088
CRect g_defaultRect_006A2088(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a2068
CRGBColor g_defaultRgbColor_006A2068;

// GLOBAL: IMPERIALISM 0x006a20b8
CPoint g_defaultPoint_006A20B8(0, 0);
// GLOBAL: IMPERIALISM 0x006a20e0
CPoint g_defaultPoint_006A20E0(0, 0);
// GLOBAL: IMPERIALISM 0x006a20c0
CRect g_defaultRect_006A20C0(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a20d0
CRect g_defaultRect_006A20D0(0, 0, 0, 0);
// GLOBAL: IMPERIALISM 0x006a20b0
CRGBColor g_defaultRgbColor_006A20B0;

// GLOBAL: IMPERIALISM 0x006a2140
double g_ScaleDefault6A2140 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a2108
double g_ScaleDefault6A2108 = DefaultGfxCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a21ac
short g_scaledShortConst_6A21AC = static_cast<short>(g_ScaleDefault6A2108 * 512.0 + 1.0);

// Nonzero CPoint defaults emitted as direct dword stores.
// GLOBAL: IMPERIALISM 0x006a2150
CPoint g_defaultPoint_006A2150(0x80, 0x80);
// GLOBAL: IMPERIALISM 0x006a2100
CPoint g_defaultPoint_006A2100(0x32, 0x1e);
// GLOBAL: IMPERIALISM 0x006a2118
CPoint g_defaultPoint_006A2118(0x5dc, 0x1c2);
// GLOBAL: IMPERIALISM 0x006a2198
CPoint g_defaultPoint_006A2198(0x32, 0x32);
// GLOBAL: IMPERIALISM 0x006a2160
CPoint g_defaultPoint_006A2160(0x50, 0x2d);
// GLOBAL: IMPERIALISM 0x006a2120
CPoint g_defaultPoint_006A2120(0x208, 0x384);
// GLOBAL: IMPERIALISM 0x006a21b0
CPoint g_defaultPoint_006A21B0(0x50, 0x2d);

extern "C" {

// GLOBAL: IMPERIALISM 0x006a3e28
short g_NavyResolveOrderRanking[14];
// GLOBAL: IMPERIALISM 0x006a3e50
short g_NavyMissionOrderRanking[14];
// GLOBAL: IMPERIALISM 0x006a3e90
short g_NavyPriorityOrderRanking[14];

float g_afWarNumberByForeignMinister[8] = {0.7f, 1.1f, 1.2f, 1.5f, 1.0f, 0.9f, 0.7f, 0.0f};
float g_afWarNumberByDefenseMinister[6] = {1.0f, 1.0f, 1.3f, 1.3f, 1.3f, 0.0f};
float g_afSeekAllianceByForeignMinister[8] = {0.6f, 0.7f, 0.7f, 0.7f, 0.8f, 0.6f, 0.6f, 0.0f};
float g_afSeekAllianceByDefenseMinister[6] = {0.7f, 1.1f, 1.3f, 0.9f, 1.0f, 0.0f};
float g_afAcceptAllianceByForeignMinister[8] = {0.5f, 0.6f, 0.6f, 0.6f, 0.7f, 0.5f, 0.5f, 0.0f};
float g_afAcceptAllianceByDefenseMinister[6] = {1.0f, 1.0f, 1.2f, 0.8f, 0.9f, 0.0f};
float g_afSeekPeaceByForeignMinister[8] = {0.4f, 0.5f, 0.5f, 0.5f, 0.6f, 0.4f, 0.4f, 0.0f};
float g_afSeekPeaceByDefenseMinister[6] = {1.1f, 1.0f, 1.3f, 0.7f, 1.1f, 0.0f};
float g_afAcceptPeaceByForeignMinister[8] = {0.4f, 0.5f, 0.5f, 0.5f, 0.6f, 0.4f, 0.4f, 0.0f};
float g_afAcceptPeaceByDefenseMinister[6] = {0.9f, 0.8f, 1.1f, 0.5f, 0.9f, 0.0f};

float g_Iterate_Linked_List_Value = 0.25f;
float g_Compute_City_Order_Value = 0.5f;
float g_Compute_Advisory_Peer_LookupTable = -0.5f;
float g_ApplyIndexedResourceDeltaScale = -1.0f / 255.0f;

// Per-unit-type military stat records (0xe-byte records, 7 shorts each), rebased
// from the earlier 0x695CD4 model: TMilitaryUnit::GetArmsCarried (0x5c3400)
// reads the category flag at record offset +0 (0x695cd2; 0x10 = counted) and the
// power/cost points at +2 (0x695cd4, the short the slot 0x8e-0x9c score family sums).

// GLOBAL: IMPERIALISM 0x0066eb88
short g_UnitTypeStatTable[30][7] = {
    {0x0026, 0x0014, 0x0001, 0x0001, 0x000a, 0x0000, 0x003c},
    {0x0032, 0x0019, 0x0001, 0x0001, 0x0023, 0x004b, 0x006e},
    {0x004b, 0x001e, 0x0001, 0x0001, 0x000a, 0x0000, 0x0078},
    {0x005e, 0x002d, 0x0001, 0x0001, 0x000a, 0x0000, 0x009a},
    {0x0023, 0x0028, 0x0001, 0x0001, 0x0046, 0x0032, 0x0094},
    {0x0028, 0x005a, 0x0001, 0x0001, 0x003c, 0x0000, 0x00ce},
    {0x000a, 0x0091, 0x001e, 0x0032, 0x0005, 0x0000, 0x00d2},
    {0x001e, 0x0014, 0x003c, 0x0046, 0x0005, 0x0000, 0x0104},
    {0x005c, 0x0030, 0x0001, 0x0001, 0x0021, 0x0000, 0x00b4},
    {0x0082, 0x0046, 0x0001, 0x0001, 0x006e, 0x0087, 0x019a},
    {0x00dc, 0x0050, 0x0001, 0x0001, 0x0021, 0x0000, 0x01b8},
    {0x00fa, 0x0064, 0x0001, 0x0001, 0x0021, 0x0000, 0x0208},
    {0x004d, 0x0064, 0x0001, 0x0001, 0x00dc, 0x006e, 0x01e0},
    {0x007d, 0x00c8, 0x0001, 0x0001, 0x00b9, 0x0000, 0x0258},
    {0x0016, 0x00fa, 0x006e, 0x00f0, 0x000a, 0x0000, 0x028a},
    {0x006e, 0x0021, 0x00b9, 0x0113, 0x000a, 0x0000, 0x0348},
    {0x00ff, 0x0082, 0x0001, 0x0001, 0x005f, 0x0000, 0x02a8},
    {0x015e, 0x00be, 0x0001, 0x0001, 0x0140, 0x00f0, 0x0708},
    {0x0258, 0x00dc, 0x0001, 0x0001, 0x0064, 0x0000, 0x075c},
    {0x02a3, 0x010e, 0x0001, 0x0001, 0x0064, 0x0000, 0x07bc},
    {0x015e, 0x00fa, 0x0001, 0x0001, 0x02bc, 0x0000, 0x07b4},
    {0x02bc, 0x0352, 0x0001, 0x0001, 0x0226, 0x0000, 0x0fc8},
    {0x0064, 0x0226, 0x01f4, 0x028a, 0x0096, 0x0000, 0x0b2c},
    {0x0258, 0x00a0, 0x0271, 0x03c0, 0x0028, 0x0000, 0x0e44},
    {0x000d, 0x000a, 0x009b, 0x0001, 0x000a, 0x0000, 0x00c1},
    {0x0030, 0x0020, 0x01c2, 0x0001, 0x001e, 0x0000, 0x0208},
    {0x00f0, 0x0078, 0x04b0, 0x0001, 0x0050, 0x0000, 0x05a0},
    {0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0},
};
// GLOBAL: IMPERIALISM 0x0066ed30
short g_UnitTypeStatDivisorTable[7] = {150, 150, 65, 75, 100, 250, 0};

short g_anTrackedOrderSortPriorityByType[12] = {2, 0, 4, 3, 1, 5, 0, 0, 0, 0, 0, 0};

// GLOBAL: IMPERIALISM 0x00696678
short g_civilianTileOrderCursorTokenTable[12] = {0,    1008, 0,    1004, 1003, 1002,
                                                 1018, 1019, 1001, 1003, 1011, 1025};

// Cursor resource ids selected by TArmyMgr's two map cursor state classifiers.
// GLOBAL: IMPERIALISM 0x00695668
short g_mapCursorTokenByStateIndex[12] = {0, 0, 1000, 0, 0, 0, 1011, 1011, 1010, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x00695680
short g_civilianMapCursorTokenByStateIndex[12] = {0,    1008, 1000, 1005, 1006, 1007,
                                                  1011, 1011, 1010, 0,    0,    0};

} // extern "C"

// GLOBAL: IMPERIALISM 0x006a5430
CSize g_tacticalTileSize(0x32, 0x1e);
// GLOBAL: IMPERIALISM 0x006a5448
CSize g_tacticalBattlefieldSurfaceSize(0x5dc, 0x1c2);
// The first store is at 0x5a6895; the initializer entry is 0x5a6890.
// GLOBAL: IMPERIALISM 0x006a5498
CSize g_tacticalUnitSpriteCellSize(0x32, 0x32);

extern "C" {

// GLOBAL: IMPERIALISM 0x006699e8
int g_anUnitTypeTacticalRangeByType[30] = {5,  5,  5,  5,  3,  3,  9,  11, 8,  8, 8, 8,  5, 5, 12,
                                           14, 10, 10, 10, 10, 10, 12, 15, 17, 5, 8, 10, 0, 0, 0};

// GLOBAL: IMPERIALISM 0x00695528
ArmyUnitCategoryStorage g_awTacticalUnitCategoryCodeBySlot[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9, 0, 0};

// GLOBAL: IMPERIALISM 0x00695380
short g_awUnitCombatClassBySlot[32] = {1, 2, 1, 1, 3, 2, 2, 1, 1, 2, 1, 1, 3, 2, 2, 1,
                                       1, 2, 1, 1, 3, 3, 2, 1, 1, 2, 3, 2, 2, 2, 0, 0};
// Stack composition class lookup (byte table at 0x6953c0); indexed [minClass + maxClass*4].
// GLOBAL: IMPERIALISM 0x006953c0
unsigned char g_abStackCompositionClassTable[4][4] = {
    {0, 0, 0, 0}, {0, 1, 0, 0}, {0, 2, 3, 0}, {0, 3, 4, 5}};
// GLOBAL: IMPERIALISM 0x006953e8
short g_anUnitStrengthWeightPercentBySlot[32] = {
    50,  50,  100, 125, 75,  150, 0, 0, 75, 100, 150, 175, 100, 200, 0, 0,
    100, 150, 225, 250, 225, 600, 0, 0, 0,  0,   0,   0,   0,   0,   0, 0};

// Per-civilian-order-type map-improvement sprite class (short table at 0x697040).
short g_anMapImprovementSpriteClassByOrderType[kCivilianUnitKindCount] = {2, 3, 1, 6, 0,
                                                                          7, 5, 4, 8};

// Per-fort-level attacker penalty percent; indexed by Province::fortLevel.
// GLOBAL: IMPERIALISM 0x00695568
int g_anFortLevelAttackerPenaltyPercentByLevel[4] = {100, 85, 75, 65};
// GLOBAL: IMPERIALISM 0x0064c808
unsigned char g_abUnitTypeBlinkEligibilityFlag[kMilitaryUnitKindCount] = {
    1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0};

// Four per-unit-type meter-scoring tables, indexed by TUnit::orderType.
// GLOBAL: IMPERIALISM 0x0064c790
int g_anWeightClassByOrderType[kMilitaryUnitKindCount] = {5,  5,  5,  5,  3,  3,  9,  11, 8,  8,
                                                          8,  8,  5,  5,  12, 14, 10, 10, 10, 10,
                                                          10, 12, 15, 17, 5,  8,  10, 0,  0,  0};
// GLOBAL: IMPERIALISM 0x0064c660
short g_anScaledFactorByOrderType[kMilitaryUnitKindCount] = {
    40, 60, 40, 40, 110, 90,  50, 30, 40, 60, 40, 40, 110, 90, 60,
    30, 50, 70, 50, 40,  110, 90, 80, 30, 40, 40, 50, 90,  90, 90};
// GLOBAL: IMPERIALISM 0x0064c6a0
float g_afPercentEfficiencyByOrderType[kMilitaryUnitKindCount] = {
    50.0f,  50.0f,  100.0f, 125.0f, 75.0f,  150.0f, 100.0f, 160.0f, 75.0f,  100.0f,
    150.0f, 175.0f, 100.0f, 200.0f, 175.0f, 300.0f, 100.0f, 150.0f, 225.0f, 250.0f,
    225.0f, 450.0f, 250.0f, 500.0f, 0.0f,   0.0f,   0.0f,   0.0f,   0.0f,   0.0f};
// GLOBAL: IMPERIALISM 0x0064c718
float g_afRandomizedMeterDecayByOrderType[kMilitaryUnitKindCount] = {
    0.0025f, 0.0015f, 0.0020f, 0.0020f, 0.0015f, 0.0020f, 0.0040f, 0.0050f, 0.0025f, 0.0015f,
    0.0015f, 0.0015f, 0.0015f, 0.0020f, 0.0030f, 0.0035f, 0.0010f, 0.0005f, 0.0005f, 0.0005f,
    0.0010f, 0.0005f, 0.0005f, 0.0005f, 0.0030f, 0.0025f, 0.0010f, 0.0020f, 0.0015f, 0.0005f};
// GLOBAL: IMPERIALISM 0x00695578
int g_anCountWeightByOrderType[kMilitaryUnitKindCount] = {
    0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 0, 0, 0};

unsigned char g_abUniversityRequirementLevelById[24][4] = {
    {1, 2, 3, 4}, {1, 2, 3, 4}, {1, 2, 3, 4}, {0, 2, 4, 6}, {0, 2, 4, 6}, {1, 1, 1, 1},
    {0, 2, 4, 6}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0},
    {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {1, 2, 3, 4},
    {1, 2, 3, 4}, {1, 2, 3, 4}, {1, 2, 3, 4}, {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 0, 0, 0}};
// GLOBAL: IMPERIALISM 0x00651030
int g_anUniversityRequirementIdByRecruitRow[9][4] = {
    {3, 4, 21, 22},  {-1, -1, -1, -1}, {0, 17, 18, -1},  {2, -1, -1, -1}, {-1, -1, -1, -1},
    {1, 20, -1, -1}, {19, -1, -1, -1}, {-1, -1, -1, -1}, {6, -1, -1, -1}};
// GLOBAL: IMPERIALISM 0x00651100
short g_awArmoryUnitActionPointsByType[30] = {40,  60, 40,  40, 110, 90, 50, 30, 40, 60,
                                              40,  40, 110, 90, 60,  30, 50, 70, 50, 40,
                                              110, 90, 80,  30, 40,  40, 50, 90, 90, 90};
// GLOBAL: IMPERIALISM 0x00651140
float g_afArmoryUnitFirepowerByType[30] = {
    50.0f,  50.0f,  100.0f, 125.0f, 75.0f,  150.0f, 100.0f, 160.0f, 75.0f,  100.0f,
    150.0f, 175.0f, 100.0f, 200.0f, 175.0f, 300.0f, 100.0f, 150.0f, 225.0f, 250.0f,
    225.0f, 450.0f, 250.0f, 500.0f, 0.0f,   0.0f,   0.0f,   0.0f,   0.0f,   0.0f};
// GLOBAL: IMPERIALISM 0x006511b8
int g_anArmoryUnitRangeByType[30] = {5,  5,  5,  5,  3,  3,  9,  11, 8,  8, 8, 8,  5, 5, 12,
                                     14, 10, 10, 10, 10, 10, 12, 15, 17, 5, 8, 10, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x00651398
float g_fArmoryFirepowerDisplayScale = 0.1f;
unsigned char g_abResourceTypeUsesHighNibbleFlag[24] = {0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0,
                                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
char g_abResourceTypeCapabilityCategory[24] = {0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// GLOBAL: IMPERIALISM 0x006963e8
unsigned char g_abResourceTypeMiniCivMentionFlag[24] = {0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
short g_anResourceTypeRequiredOrderType[24] = {2,  5,  3,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                               -1, -1, -1, -1, -1, 2,  2,  6,  5,  -1, -1, 0};
// Per-resourceType "always-qualifies" flag; same caller as above.
unsigned char g_abResourceTypeAlwaysQualifies[24] = {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Per-gateFlag eligibility flag; only indices 0-3 are meaningful (gateFlag's real range).
unsigned char g_abGateFlagQualifies[24] = {
    0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

short g_hexColumnStepByDirection[6] = {1, 2, 1, -1, -2, -1};
short g_hexRowStepByDirection[6] = {-1, 0, 1, 1, 0, -1};

unsigned char g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainCount] = {1, 1, 0, 0,
                                                                              0, 0, 1, 1};

short g_anStrategicTerrainNeighborLinkPriority[kStrategicTerrainCount] = {10, 4, 7, 6, 8, 0, 9, 5};

int g_nNextRegionMarkerId = 1;

short g_awTileSpriteVariantOffsetTable38[16][2] = {
    {0x140, 0x140}, {0, 0},         {0x200, 0x200}, {0x240, 0x240}, {0x300, 0x300}, {0x1c0, 0x1c0},
    {0x3c0, 0x3c0}, {0x700, 0x700}, {0x080, 0x080}, {0x0c0, 0x2c0}, {0x100, 0x100}, {0x180, 0x180},
    {0xb80, 0xb80}, {0x040, 0x040}, {0, 0},         {0xc00, 0xc00}};
short g_awTileSpriteVariantOffsetTable39[8] = {0x140, 0x980, 0x9c0, 0xa00, 0xa40, 0, 0, 0};
short g_awTileSpriteVariantOffsetTable3a[16][5] = {
    {0x140, 0x140, 0, 0, 0}, {0, 0, 0, 0, 0},         {0x280, 0x280, 0, 0, 0},
    {0x340, 0x340, 0, 0, 0}, {0x300, 0x300, 0, 0, 0}, {0x680, 0x680, 0, 0, 0},
    {0x940, 0x940, 0, 0, 0}, {0x740, 0x740, 0, 0, 0}, {0x440, 0x440, 0, 0, 0},
    {0x4c0, 0x780, 0, 0, 0}, {0x540, 0x540, 0, 0, 0}, {0x640, 0x6c0, 0x900, 0x380, 0xbc0},
    {0xbc0, 0, 0, 0, 0x400}, {0x400, 0, 0, 0, 0},     {0, 0, 0, 0, 0xc40},
    {0xc40, 0, 0, 0, 0}};
short g_awTileSpriteVariantOffsetTable3b[16][2] = {
    {0, 0},         {0, 0},         {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0x800, 0x800},
    {0x480, 0x480}, {0x500, 0x7c0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}};

TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[14] = {
    {{0, 0, 0, 0, 0, 0, -1, 0, 0}},        {{0, 0, 100, 600, 0, 2, -1, 1, 0}},
    {{0, 0, 95, 1000, 0, 4, -1, 1, 0}},    {{300, 5, 90, 900, 4, 0, 1, 3, 1}},
    {{600, 6, 80, 1700, 3, 0, 0, 2, 1}},   {{0, 0, 95, 900, 0, 8, -1, 1, 0}},
    {{0, 0, 100, 600, 0, 4, -1, 1, 0}},    {{300, 7, 80, 700, 7, 0, 2, 5, 2}},
    {{500, 8, 45, 1200, 5, 0, 3, 3, 2}},   {{1000, 10, 40, 1800, 6, 0, 0, 4, 3}},
    {{0, 0, 75, 1200, 0, 16, -1, 1, 0}},   {{600, 9, 50, 1000, 8, 0, 1, 6, 3}},
    {{2000, 13, 30, 2800, 7, 0, 3, 5, 4}}, {{1800, 13, 45, 2200, 9, 0, 2, 6, 4}}};

// GLOBAL: IMPERIALISM 0x006a3ec8
int g_aCategoryMetricBaselineAverage[4] = {0};

// GLOBAL: IMPERIALISM 0x0065a9c0
float g_fMissionScoreNormalizationDivisor = 5000.0f;

// Initial/reset score for TScatteredShipsMission.
// GLOBAL: IMPERIALISM 0x0065a9c8
float g_fScatteredShipsMissionDefaultScore = 0.001f;

// GLOBAL: IMPERIALISM 0x006a3a54
short g_nArmsBasicResourceOfferSplitCount = 0;
// GLOBAL: IMPERIALISM 0x006a3a58
short g_nArmsAdvancedResourceOfferSplitCount = 0;
// GLOBAL: IMPERIALISM 0x006a3a88
float g_afNationOrderQueueDivergence[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3ac0
float g_afNationOrderQueueDivergenceMirror[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3ae0
float g_afNationMobileUnitDivergence[kMajorNationCount] = {0};
// GLOBAL: IMPERIALISM 0x006a3b20
float g_afNationWeightedMilitaryOrderScore[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3b50
float g_afNationCombinedUnitDivergence[kMajorNationCount] = {0};
// GLOBAL: IMPERIALISM 0x006a3b88
float g_afNationMobileUnitScore[kMajorNationCount] = {0};

// GLOBAL: IMPERIALISM 0x00698120
IndustryCapabilityClassSlotEntry g_aIndustryCapabilityClassSlotTable[14] = {
    {-1, {0x0, 0x0, 0x0, 0x0, 0x64, 0x258, 0x0, 0x2}},
    {-1, {0x1, 0x0, 0x0, 0x0, 0x5f, 0x3e8, 0x0, 0x4}},
    {-1, {0x1, 0x0, 0x12c, 0x5, 0x5a, 0x384, 0x4, 0x0}},
    {1, {0x3, 0x1, 0x258, 0x6, 0x50, 0x6a4, 0x3, 0x0}},
    {0, {0x2, 0x1, 0x0, 0x0, 0x5f, 0x384, 0x0, 0x8}},
    {-1, {0x1, 0x0, 0x0, 0x0, 0x64, 0x258, 0x0, 0x4}},
    {-1, {0x1, 0x0, 0x12c, 0x7, 0x50, 0x2bc, 0x7, 0x0}},
    {2, {0x5, 0x2, 0x1f4, 0x8, 0x2d, 0x4b0, 0x5, 0x0}},
    {3, {0x3, 0x2, 0x3e8, 0xa, 0x28, 0x708, 0x6, 0x0}},
    {0, {0x4, 0x3, 0x0, 0x0, 0x4b, 0x4b0, 0x0, 0x10}},
    {-1, {0x1, 0x0, 0x258, 0x9, 0x32, 0x3e8, 0x8, 0x0}},
    {1, {0x6, 0x3, 0x7d0, 0xd, 0x1e, 0xaf0, 0x7, 0x0}},
    {3, {0x5, 0x4, 0x708, 0xd, 0x2d, 0x898, 0x9, 0x0}},
    {2, {0x6, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
};

// GLOBAL: IMPERIALISM 0x0065c25e
short g_aNavalIntelligenceAccuracyProfiles[6][6] = {
    {0, 50, 20, 30, 40, 30},  {30, 50, 20, 30, 50, 30}, {20, 40, 35, 25, 55, 30},
    {15, 30, 50, 20, 65, 20}, {15, 20, 65, 15, 70, 20}, {10, 10, 80, 10, 80, 10},
};

// GLOBAL: IMPERIALISM 0x006a43f4
bool g_bPerfectNavalIntelligenceCheat = false;

// GLOBAL: IMPERIALISM 0x0066ef30
MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable[23] = {
    {0, 0},  {9, 0},  {16, 0}, {14, 0}, {17, 0}, {8, 0},  {2, 0},  {5, 0},
    {12, 0}, {11, 0}, {13, 0}, {6, 0},  {6, 0},  {6, 0},  {6, 0},  {4, 0},
    {7, 0},  {1, 0},  {1, 0},  {10, 0}, {15, 0}, {10, 0}, {10, 0},
};

// Defend-province / mission priority-vector normalization (0x53e6e0 / 0x53ea70 family).
// GLOBAL: IMPERIALISM 0x0065a8f0
extern const float g_AttackProvinceMissionReadinessThreshold = 1.0f;
// GLOBAL: IMPERIALISM 0x0065a8f8
extern const float g_DefendProvinceMissionCrossSupportFloorScale = 0.8f;
// GLOBAL: IMPERIALISM 0x0065a8fc
extern const float g_MissionResourceWeightScale = 1.1f;
// GLOBAL: IMPERIALISM 0x0065a900
extern const float g_BlockadePortMissionThreatFloor = 10.0f;
// GLOBAL: IMPERIALISM 0x0065a904
extern const float g_BlockadePortMissionThreatScale = 0.5f;
// GLOBAL: IMPERIALISM 0x0065a910
extern const float g_NavyMissionIndustrialCostWeights[4] = {1.0f, 1.0f, 1.0f, 1.0f};
// Fourteen-entry signed lookup object following the industrial-cost weights.
// GLOBAL: IMPERIALISM 0x0065a920
extern const int g_NavyMissionIndustrialCostTrailingLookup[14] = {
    -1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7,
};
// GLOBAL: IMPERIALISM 0x0065a958
extern const float g_NavyMissionQueuedWeightDeficitScale = 1.0f;
// GLOBAL: IMPERIALISM 0x0065a95c
extern const float g_InvadeMissionSuppressedPriorContributionScale = 0.0f;
// GLOBAL: IMPERIALISM 0x0065a960
extern const float g_NavyMissionSimilarityExcessBlend = 0.25f;
// GLOBAL: IMPERIALISM 0x0065a968
// Difficulty-row / fort-level-column resource scaling for attack-province missions.
extern const float g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel[5][4] = {
    {1.9f, 2.3f, 2.5f, 2.7f},
    {1.9f, 2.3f, 2.5f, 2.7f},
    {2.0f, 2.3f, 2.5f, 2.7f},
    {2.1f, 2.3f, 2.5f, 2.7f},
    {2.3f, 2.5f, 2.7f, 2.9f}};
// GLOBAL: IMPERIALISM 0x0065a9b8
extern const float g_MissionPositiveFallback = 1.0f;
// GLOBAL: IMPERIALISM 0x0065aa10
extern const double g_PortZoneFriendlyMissionScoreMultiplier = 1.5;
// GLOBAL: IMPERIALISM 0x0065aa18
extern const double g_PortZoneForeignMissionScoreMultiplier = 1.25;
// GLOBAL: IMPERIALISM 0x0065aa24
extern const float g_MissionEmptyResourceWeight = 100.0f;
// GLOBAL: IMPERIALISM 0x0065aa48
extern const double g_ArmyMissionEligibleUnitStrengthScale = 0.002;
// GLOBAL: IMPERIALISM 0x00697870
short g_awTacticalCompositionReferenceProfiles[20] = {40, 27, 0,  17, 16, 27, 36, 0, 17, 20,
                                                      26, 31, 20, 23, 0,  40, 22, 0, 38, 0};
short g_Populate_Beachhead_Mission_LookupTable[0x10] = {40, 40, 20, 0,  40, 30, 30, 0,
                                                        35, 35, 0,  30, 0,  20, 80, 0};
const short g_NavyOrderDistributionCategoryWeights[4] = {40, 30, 30, 0};
// GLOBAL: IMPERIALISM 0x006978c8
extern const float g_MissionOrderDistanceDecayWeightTable[6] = {1.0f,   0.8f,    0.64f,
                                                                0.512f, 0.4096f, 0.32768f};

// GLOBAL: IMPERIALISM 0x00697980
float g_ArmyMissionDotProductWeights[5] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
// GLOBAL: IMPERIALISM 0x006978f8
float g_ArmyMissionCandidateScoreTable[24] = {
    0.0f, 0.01f, 0.02f, 0.03f, 0.04f, 0.05f, 0.0f, 0.01f, 0.02f, 0.03f, 0.04f, 0.05f,
    0.0f, 0.01f, 0.02f, 0.03f, 0.04f, 0.05f, 0.0f, 0.01f, 0.02f, 0.03f, 0.04f, 0.05f};

// GLOBAL: IMPERIALISM 0x0065aa30
extern const double g_BeachheadMissionPriorityNormalization = 100.0;

float g_afAdvisoryMissionTierThresholdByMinisterSkill[5][6] = {
    {1.5f, 1.5f, 2.5f, 0.0f, 2.25f, 2.0f},  {1.75f, 1.75f, 2.5f, 0.0f, 2.25f, 2.25f},
    {2.0f, 2.0f, 2.0f, 0.0f, 1.5f, 1.5f},   {2.0f, 2.0f, 3.0f, 0.0f, 2.0f, 2.0f},
    {1.5f, 1.5f, 2.5f, 0.0f, 1.75f, 1.75f},
};

// TAutoGreatPower slot 0x9d / 0xa7 scoring constants: -100.0f and 0.5 (double).
float g_Compute_Advisory_Map_Value = -100.0f;
double g_Evaluate_Advisory_Case11_Value = 0.5;
extern const float g_Compute_Advisory_Zero = 0.0f;
double g_Compute_Advisory_MinusSix = -6.0;
double g_Compute_Advisory_MinusHundred = -100.0;
// Float twin of the -6.0 double above (metric-4 denominator in 0x004e8750).
float g_Compute_Advisory_MinusSixFloat = -6.0f;
double g_Compute_Advisory_Hundred = 100.0;
double g_Compute_Advisory_OnePointFive = 1.5;

short g_Rebuild_Primary_Nation_Value[5][kNationSlotCount] = {
    {20, 20, 40, 30, 30, 10, 0, 20, 20, 20, 20, 20, 0, 10, 10, 10, 10, 10, 5, 0, 5, 0, 0},
    {5, 5, 10, 5, 5, 2, 0, 20, 10, 15, 8, 10, 0, 5, 5, 0, 0, 10, 5, 0, 5, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 20, 10, 24, 8, 19, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0}};

// GLOBAL: IMPERIALISM 0x0066f050
char* g_pNationInfoEmptyText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0066f058
short g_anAbilityStatusPictureIndex[29] = {0,  1,  3,  2,  7,  5,  6,  9,  10, 4,
                                           8,  16, 12, 19, 22, 11, 17, 13, 14, 21,
                                           15, 18, 26, 20, 23, 28, 24, 25, 27};

// GLOBAL: IMPERIALISM 0x0066f0a6
short g_overlaySfxSeasonWord = 10;

// Advisor-newspaper list-building literals (TNewspaperView cluster).
// GLOBAL: IMPERIALISM 0x00695760
char g_szListSeparator[] = ", ";
// GLOBAL: IMPERIALISM 0x00698494
char g_szPlusPrefix[] = "+";
// GLOBAL: IMPERIALISM 0x00698498
char g_szListConjunction[] = " and ";

// GLOBAL: IMPERIALISM 0x0066fad0
double g_dMasterVolumeExponentScale = 0.092;

} // extern "C"

#include "game/map/TZone.h"
#include "game/navy/TOcean.h"
#include "game/navy/TTaskForce.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TMinor.h"
#include "game/city_ui/TCivMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"

// GLOBAL: IMPERIALISM 0x006a4780
POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

// GLOBAL: IMPERIALISM 0x00656f60
extern const char* const g_pszEmptyTextPointer = g_szEmptyString;

TZone* g_pMapActionContextListHead = 0;
// GLOBAL: IMPERIALISM 0x006a3fbc
TOcean* g_pActiveMapOrderContext = 0;
TMapMgr* g_pGlobalMapState = 0;
TCivMgr* g_pSelectedCivilianOrderState = 0;
// GLOBAL: IMPERIALISM 0x006a3ff0
int g_nOceanDialogSeedViewportOffsetX = 0;
// GLOBAL: IMPERIALISM 0x006a3ff4
int g_nOceanDialogSeedViewportOffsetY = 0;
// GLOBAL: IMPERIALISM 0x006a33b0
int g_wMapDialogViewportTileSpan;
// GLOBAL: IMPERIALISM 0x0065c2f0
short g_awMapContextActionLabelTokenByCommand[17] = {0,     0x3f0, 0x3f2, 0x3f2, 0x3f2, 0x3f2,
                                                     0x3f2, 0x3f2, 0x3f2, 0x3f1, 0x3f3, 0x3f3,
                                                     0x3f6, 0x3f8, 0x3f4, 0x3f5, 0x3f7};
// GLOBAL: IMPERIALISM 0x0066ad58
int g_anTechItemResearchCostByTechId[29] = {
    0,     0,     1000,  1000,  1500,  1500,   1500,   1500,   3000,  3000,
    3000,  6000,  7000,  10000, 12000, 12000,  12000,  12000,  12000, 25000,
    20000, 40000, 40000, 40000, 40000, 100000, 120000, 150000, 150000};
// GLOBAL: IMPERIALISM 0x00695c50
short g_aInitialCityRecruitmentOrderProfiles[9][7] = {
    {0, 10, 2, -1, 0, 1500, 4}, {1, 10, 2, -1, 0, 500, 4},  {2, 10, 2, -1, 0, 1000, 4},
    {3, 10, 2, -1, 0, 1000, 4}, {4, 10, 2, -1, 0, 2000, 4}, {5, 10, 2, -1, 0, 1000, 4},
    {6, 10, 2, -1, 0, 1000, 4}, {7, 10, 2, -1, 0, 2000, 4}, {8, 10, 2, -1, 0, 5000, 4}};
// GLOBAL: IMPERIALISM 0x00695cd0
short g_aUnitOrderCostProfileByAbilityId[0x1e][7] = {
    {0, -1, 0, -1, 0, 0, 1},      {1, 16, 1, -1, 0, 200, 1},   {2, 16, 1, -1, 0, 500, 1},
    {3, 16, 1, -1, 0, 1000, 2},   {4, 16, 1, 5, 1, 100, 1},    {5, 16, 1, 5, 1, 500, 2},
    {6, 16, 2, 5, 1, 1000, 2},    {7, 16, 2, -1, 0, 1000, 2},  {8, -1, 0, -1, 0, 0, 1},
    {9, 16, 2, -1, 0, 3000, 1},   {10, 16, 2, -1, 0, 3000, 1}, {11, 16, 2, -1, 0, 4000, 2},
    {12, 16, 2, 5, 1, 2000, 1},   {13, 16, 2, 5, 1, 3500, 2},  {14, 16, 4, 5, 1, 5000, 2},
    {15, 16, 4, -1, 0, 5000, 2},  {16, -1, 0, -1, 0, 0, 1},    {17, 16, 4, -1, 0, 5000, 2},
    {18, 16, 4, -1, 0, 5000, 2},  {19, 16, 4, -1, 0, 7000, 2}, {20, 16, 4, 12, 4, 5000, 2},
    {21, 16, 10, 12, 4, 9000, 2}, {22, 16, 6, 12, 4, 5000, 2}, {23, 16, 8, -1, 0, 9000, 2},
    {24, 16, 2, -1, 0, 5000, 4},  {25, 16, 2, -1, 0, 7000, 4}, {26, 16, 3, -1, 0, 9000, 4},
    {27, -1, 0, -1, 0, 0, 4},     {28, -1, 0, -1, 0, 0, 4},    {29, -1, 0, -1, 0, 0, 4}};
// GLOBAL: IMPERIALISM 0x0066ac10
TechPrerequisitePair g_aTechItemPrerequisitePairs[34] = {
    {0, 0},  {0, 0},  {0, 0}, {0, 0},  {0, 0},  {1, 0},  {1, 0},  {0, 0},  {7, 3},
    {0, 0},  {2, 0},  {0, 0}, {6, 0},  {0, 0},  {11, 0}, {0, 0},  {8, 0},  {10, 0},
    {10, 0}, {0, 0},  {7, 0}, {15, 0}, {13, 0}, {5, 12}, {9, 10}, {14, 0}, {19, 0},
    {24, 0}, {26, 0}, {0, 0}, {25, 0}, {25, 0}, {25, 0}, {0, 0}};
// GLOBAL: IMPERIALISM 0x006a3ed8
TTaskForce* g_pCachedMapActionContext = 0;
TSoundPlayer* g_pSfxPlaybackSystem = 0;
// GLOBAL: IMPERIALISM 0x006a4520
short g_randomAudioCuePollCounter = 0;
// GLOBAL: IMPERIALISM 0x006a43cc
TTradeMgr* g_pTradeMgr = 0;
// GLOBAL: IMPERIALISM 0x006a4220
CString g_cstrCountryNameSettingValue;
// GLOBAL: IMPERIALISM 0x006a4268
TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture = 0;

extern "C" {
// Five fort levels occupy 0x65318a..0x653193; the civilian cost table starts at 0x653194.
short g_awEngineerFortBuildCostByLevel[5] = {5000, 7500, 10000, 0, 0};
// One cost per StrategicTerrainKind; TCivMgr::classTCivMgr starts at 0x6531f8.
int g_adwEngineerRailBuildCostByTerrainType[kStrategicTerrainCount] = {100, 150, 200, 400,
                                                                       300, 0,   150, 100};
int g_adwCivilianWorkOrderCostByClass[16] = {100, 1000, 5000, -1, -1, -1, 0, 1,
                                             -1,  -1,   2,    3,  4,  -1, 5, 6};

int g_nMapActionContextCount = 0;
void* g_pMapActionContextDistanceCache = 0;
int g_nMapActionContextDistanceCacheSizedFor = -1;

// GLOBAL: IMPERIALISM 0x006a42dc
bool g_bRandomMapDeveloperCheatFlag = false;
// GLOBAL: IMPERIALISM 0x006a42f0
POINT g_ptTurnTransitionModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x00698bec
char g_szConanCheatFileName[] = "Conan";

// GLOBAL: IMPERIALISM 0x0066d810
short g_aTradeDealCategoryOrder[0x11] = {13, 14, 15, 16, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3, 4, 5, 6};
// Multiplicative identity used by TTradeMgr::Power.
// GLOBAL: IMPERIALISM 0x0066d8e0
extern const double g_TradePowerIdentity = 1.0;

// Initial price for each of the 17 trade-item categories.
// GLOBAL: IMPERIALISM 0x0069a910
extern const short g_aTradeItemBasePriceByCategory[0x11] = {
    100, 100, 100, 100, 100, 300, 100, 100, 300, 300, 300, 300, 300, 900, 900, 900, 900};

// GLOBAL: IMPERIALISM 0x0066dad0
const unsigned int g_tradeCommodityRowTagTable[17] = {
    kControlTagRs0Sp, kControlTagRs1Sp, kControlTagRs2Sp, kControlTagRs3Sp, kControlTagRs4Sp,
    kControlTagRs5Sp, kControlTagRs6Sp, kControlTagMa0Sp, kControlTagMa1Sp, kControlTagMa2Sp,
    kControlTagMa3Sp, kControlTagMa4Sp, kControlTagMa5Sp, kControlTagGd0Sp, kControlTagGd1Sp,
    kControlTagGd2Sp, kControlTagGd3Sp};

// GLOBAL: IMPERIALISM 0x006a58c8
COLORREF g_defaultDropShadowTextColor = 0;
// GLOBAL: IMPERIALISM 0x0066aba4
short g_anCapabilityPriorityRangeData[54] = {1,  5,  6,  10, 6,  10, 6,  10, 6,  10, 11, 15, 11, 15,
                                             16, 20, 21, 25, 21, 25, 26, 30, 26, 30, 31, 35, 31, 35,
                                             36, 40, 41, 45, 41, 45, 46, 50, 51, 55, 56, 60, 56, 60,
                                             56, 60, 61, 65, 61, 65, 66, 70, 66, 70, 0,  0};
// GLOBAL: IMPERIALISM 0x006a601c
int DAT_006a601c = 0;

// GLOBAL: IMPERIALISM 0x006942a8
extern "C" const char s_DataDirectoryPath[] = "Data/";
// GLOBAL: IMPERIALISM 0x006942fc
extern "C" const char s_IrgGlobPattern[] = "*.irg";
// GLOBAL: IMPERIALISM 0x006942b4
extern "C" const char s_NoLanguageFilesMessage[] =
    "No language files are present. Unable to start Imperialism.";
// Out-of-memory new-handler box (ShowOutOfMemoryErrorNewHandler, 0x412d90).
// GLOBAL: IMPERIALISM 0x006941f0
extern "C" const char s_OutOfMemoryText[] = "Out of Memory!!!";
// GLOBAL: IMPERIALISM 0x00694204
extern "C" const char s_ErrorCaption[] = "Error!!!!!";
// GLOBAL: IMPERIALISM 0x00698bf4
extern "C" const char s_PictWvGobPathFormat[] = "Data/PictWv%d.gob";
// GLOBAL: IMPERIALISM 0x0069b810
extern "C" const char s_MissingFileSuffix[] = "' is missing.";
// GLOBAL: IMPERIALISM 0x0069b820
extern "C" const char s_MissingFilePrefix[] = "A file required by the program, '";
// GLOBAL: IMPERIALISM 0x00695188
extern "C" const char s_MissingRequiredFileFormat[] =
    "A file required by the program, '%s,' is missing.";
// GLOBAL: IMPERIALISM 0x006951c4
extern "C" const char s_BmpResourceNameFormat[] = "%d.BMP";
// GLOBAL: IMPERIALISM 0x0069b6b4
extern "C" const char s_TurnEventCursorNameFormat[] = "~C%d";
// GLOBAL: IMPERIALISM 0x0069b6bc
extern "C" const char s_SourcePathUViewMgr[] = "D:\\Ambit\\Cross\\UViewMgr.cpp";
// GLOBAL: IMPERIALISM 0x006973d0
extern "C" const char s_SourcePathUMapDlog[] = "D:\\Ambit\\Cross\\UMapDlog.cpp";
// GLOBAL: IMPERIALISM 0x00698470
extern "C" const char s_SourcePathUNewspaper[] = "D:\\Ambit\\Cross\\UNewspaper.cpp";
// GLOBAL: IMPERIALISM 0x00698040
extern "C" const char s_SourcePathUMultiplayerMgr[] = "D:\\Ambit\\Cross\\UMultiplayerMgr.cpp";
// GLOBAL: IMPERIALISM 0x006983c8
extern "C" const char s_SourcePathUNavy[] = "D:\\Ambit\\Cross\\UNavy.cpp";
// GLOBAL: IMPERIALISM 0x00699ff4
extern "C" const char s_SourcePathUTacViews[] = "D:\\Ambit\\Cross\\UTacViews.cpp";
// GLOBAL: IMPERIALISM 0x0069b740
extern "C" const char s_SourcePathUViewMgrMore[] = "D:\\Ambit\\Cross\\UViewMgr.more.cpp";
// GLOBAL: IMPERIALISM 0x00696c58
extern "C" const char s_SourcePathUHelpMgr[] = "D:\\Ambit\\Cross\\UHelpMgr.cpp";
// Signed source-row offsets into the strategic-map unit overlay atlas.
// GLOBAL: IMPERIALISM 0x00696d20
extern "C" short g_anStrategicMapOverlaySourceRowByIconId[28] = {
    0,    798,  114,  228, 342, -114, 684, -114, -114, -114, -114, -114, -114, -114,
    -114, -114, -114, 0,   0,   -114, 798, 570,  456,  0,    0,    0,    0,    0};
// GLOBAL: IMPERIALISM 0x00696860
extern "C" const char s_SourcePathUDefenseMinister[] = "D:\\Ambit\\Cross\\UDefenseMinister.cpp";
// GLOBAL: IMPERIALISM 0x0069573c
extern "C" const char s_SourcePathUArmyMgr[] = "D:\\Ambit\\Cross\\UArmyMgr.cpp";
// GLOBAL: IMPERIALISM 0x006962e8
extern "C" const char s_SourcePathUCityDialogs[] = "D:\\Ambit\\Cross\\UCityDialogs.cpp";
// GLOBAL: IMPERIALISM 0x00696d68
extern "C" const char s_SourcePathUMacViewMgr[] = "D:\\Ambit\\Cross\\UMacViewMgr.cpp";
// GLOBAL: IMPERIALISM 0x006992f0
extern "C" const char s_SourcePathUSmallViews[] = "D:\\Ambit\\Cross\\USmallViews.cpp";
// GLOBAL: IMPERIALISM 0x00696310
extern "C" const char g_szCityProductionUniversityPrefix[] = "University: ";
// GLOBAL: IMPERIALISM 0x00696320
extern "C" const char g_szCityProductionArmoryPrefix[16] = {
    'A', 'r', 'm', 'o', 'r', 'y', ':', ' ', '\0', '\0', '\0', '\0', 'S', 'h', 'i', 'p'};
// GLOBAL: IMPERIALISM 0x0069632c
extern "C" const char g_szCityProductionShipyardPrefix[] = "Shipyard: ";
// GLOBAL: IMPERIALISM 0x00695798
extern "C" const char g_szDoubleQuote[] = "\"";
// GLOBAL: IMPERIALISM 0x0069a7f8
extern "C" const char s_SourcePathUTestDialogs[] = "D:\\Ambit\\Cross\\UTestDialogs.cpp";
// GLOBAL: IMPERIALISM 0x00696508
short g_shipyardQueueIconLeftBySlot[8] = {4, 4, 3, 2, 4, 4, 3, 2};
extern "C" const char s_SourcePathUArmyViews[] = "D:\\Ambit\\Cross\\UArmyViews.cpp";
extern "C" const char s_SourcePathUOceanViews[] = "D:\\Ambit\\Cross\\UOceanViews.cpp";
// GLOBAL: IMPERIALISM 0x00696ae0
extern "C" const char s_SourcePathUDiplomacyViews[] = "D:\\Ambit\\Cross\\UDiplomacyViews.cpp";
// GLOBAL: IMPERIALISM 0x006964b0
extern "C" const char s_SourcePathUCityMinister[] = "D:\\Ambit\\Cross\\UCityMinister.cpp";
// GLOBAL: IMPERIALISM 0x0069943c
extern "C" const char s_SourcePathUSuperMap[] = "D:\\Ambit\\Cross\\USuperMap.cpp";
// GLOBAL: IMPERIALISM 0x0069aa94
extern "C" const char s_SourcePathUTradeViews[] = "D:\\Ambit\\Cross\\UTradeViews.cpp";
// GLOBAL: IMPERIALISM 0x006984cc
extern "C" const char s_SourcePathUOcean[] = "D:\\Ambit\\Cross\\UOcean.cpp";
static inline double DefaultMiniMapViewportCoordinateScale() {
  return 0.015625;
}

static double s_miniMapViewportCoordinateScale = DefaultMiniMapViewportCoordinateScale();
// GLOBAL: IMPERIALISM 0x006a460c
short g_defaultMarkerBoxWidth = static_cast<short>(s_miniMapViewportCoordinateScale * 512.0 + 1.0);

// Profile string keys used by LoadProfileStringAndAssignSharedRef during multiplayer init.
// GLOBAL: IMPERIALISM 0x00698010
extern "C" const char s_GameName[] = "GameName";
// GLOBAL: IMPERIALISM 0x0069801c
extern "C" const char s_PlayerName[] = "PlayerName";

// InitInstance registry/profile literals (.rdata pointer table @ 0x0063e038).
// GLOBAL: IMPERIALISM 0x006941a8
extern "C" const char s_ProfileLiteralIMPERIALISM[] = "IMPERIALISM";
// GLOBAL: IMPERIALISM 0x006941b8
extern "C" const char s_ProfileKeyLanguage[] = "Language";
// GLOBAL: IMPERIALISM 0x006941c4
extern "C" const char s_ProfileKeyAutoRes[] = "AutoRes";
// GLOBAL: IMPERIALISM 0x006941d0
extern "C" const char s_ProfileSectionSettings[] = "Settings";
// GLOBAL: IMPERIALISM 0x006941dc
extern "C" const char s_ProfileAppTitleImperialism[] = "Imperialism";
// GLOBAL: IMPERIALISM 0x006941ec
extern "C" const char s_RegistryCompanyNameSSI[] = "SSI";
// GLOBAL: IMPERIALISM 0x0063e038
extern "C" const char* const g_pRegistryCompanyKey = s_RegistryCompanyNameSSI;
// GLOBAL: IMPERIALISM 0x0063e03c
extern "C" const char* const g_pRegistryAppKey = s_ProfileAppTitleImperialism;
// GLOBAL: IMPERIALISM 0x0063e040
extern "C" const char* const g_pRegistrySettingsSection = s_ProfileSectionSettings;
// GLOBAL: IMPERIALISM 0x0063e044
extern "C" const char* const g_pRegistrySettingsSectionAlt = s_ProfileSectionSettings;
// GLOBAL: IMPERIALISM 0x0063e048
extern "C" const char* const g_pRegistryAutoResKey = s_ProfileKeyAutoRes;
// GLOBAL: IMPERIALISM 0x0065ddc8
char* g_pGamePreferencesSharedText = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0065ddcc
extern "C" const char* const g_pGamePreferencesAutoResKey = s_ProfileKeyAutoRes;
// GLOBAL: IMPERIALISM 0x0065dde0
extern const int g_anGamePreferenceIndexByRow[5] = {3, 2, 8, 10, 0};
// GLOBAL: IMPERIALISM 0x0063e04c
extern "C" const char* const g_pRegistryLanguageKey = s_ProfileKeyLanguage;
// GLOBAL: IMPERIALISM 0x0063e050
extern "C" const char* const g_pRegistryProfileAppName = s_ProfileLiteralIMPERIALISM;

#include "decomp_types.h"
char g_szEmptyString[1] = {0};

// GLOBAL: IMPERIALISM 0x006a4490
extern "C" unsigned short g_awCivilianLegendSelectionCountsBySlot[16] = {0};

// GLOBAL: IMPERIALISM 0x00698ee0
extern "C" int g_anArmyToolbarCategoryByUnitType[30] = {
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9};

// GLOBAL: IMPERIALISM 0x00662b98
const int g_anDevelopableResourceTypesByCivilianClass[9][4] = {
    {3, 4, 0x15, 0x16}, {-1, -1, -1, -1},   {0, 0x11, 0x12, -1}, {2, -1, -1, -1}, {-1, -1, -1, -1},
    {1, 0x14, -1, -1},  {0x13, -1, -1, -1}, {-1, -1, -1, -1},    {6, -1, -1, -1}};

// GLOBAL: IMPERIALISM 0x00698fc8
short g_aDeveloperYieldIconAnchors[4][2] = {{540, 353}, {588, 353}, {540, 378}, {588, 378}};

// GLOBAL: IMPERIALISM 0x00698fe0
short g_anDevelopmentIconStripBaseXByCivilianClass[9] = {228, -1, 0, 114, -1, 798, 912, 1064, 684};

// GLOBAL: IMPERIALISM 0x698f58
extern "C" short g_anTargetTileProfileByCivilianClassAndSlot[45] = {
    8,  9, -1, -1, -1, 8,  9,  10, 11, 12, 6,  5, 2,  -1, -1, 13, -1, -1, -1, -1, -1, -1, -1,
    -1, 0, 3,  7,  -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, 0,  10, 11, 12, -1, -1};

// GLOBAL: IMPERIALISM 0x006a5a00
CPoint g_offerDeskSheetPosition(45, 128);
// GLOBAL: IMPERIALISM 0x006a5a28
CPoint g_offerDeskOffscreenPosition(2000, 2000);
// GLOBAL: IMPERIALISM 0x00698ab0
int g_nRandomMapSelectedNationSlot = -1;
// Rank separator drawn between the high-score rank number and the player name.
// GLOBAL: IMPERIALISM 0x00698ab4
char s_szRankDotSeparator[] = ". ";
// GLOBAL: IMPERIALISM 0x00698ae0
char g_szCountryNameProfileKey[] = "CountryName";

// Turn-flow cooldown defer counter and side flag (IsTurnFlowCooldownActiveAndResetExpiredState).
// GLOBAL: IMPERIALISM 0x006a43c4
short g_nTurnCooldownDeferCounter = 0;
// GLOBAL: IMPERIALISM 0x006a43c0 — set once scenario/turn-flow bootstrap completes.
bool g_bTurnFlowBootstrapComplete = false;
// GLOBAL: IMPERIALISM 0x006a43f0 — nonzero during multiplayer scenario setup.
bool g_bMultiplayerScenarioSetupActive = false;
// GLOBAL: IMPERIALISM 0x00698b10
short g_nTurnCooldownSideFlag = 1;

// GLOBAL: IMPERIALISM 0x00698b18
extern "C" short g_aDefaultNationSetupPolicyProfiles[kMajorNationCount][4] = {
    {1, 2, 3, 3}, {2, 2, 5, 2}, {2, 1, 4, 1}, {2, 3, 3, 3},
    {2, 3, 2, 4}, {2, 2, 1, 3}, {2, 0, 4, 0}};

// GLOBAL: IMPERIALISM 0x00698c0c
extern "C" const char s_Chunk[] = "Chunk";

TextStyle g_UiResourceEntryDefaultTextStyle = {0, 0, 0, 0};

} // extern "C"

// GLOBAL: IMPERIALISM 0x0066db50
const char* g_cstrTradeTotalsBalanceSubstitution = g_szEmptyString;

#include "game/net/TWNetSessionManager.h"

// GLOBAL: IMPERIALISM 0x006a13e0
CList<TView*, TView*> g_UiWidgetBuildStack;

// GLOBAL: IMPERIALISM 0x006a5ed8
POINT g_ptNetworkModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a5f10
CArray<WNetSelectionRecord*, WNetSelectionRecord*> g_WNetSerializedPtrArrayA;
// GLOBAL: IMPERIALISM 0x006a5f28
CArray<WNetSelectionRecord*, WNetSelectionRecord*> g_WNetSerializedPtrArrayB;
// GLOBAL: IMPERIALISM 0x006a5f40
CList<void*, void*> g_WNetPendingPacketList(10);

// Suppresses the WNetMgr.cpp assertion for an unknown DirectPlay system-message code.
// GLOBAL: IMPERIALISM 0x006a6020
int g_suppressUnexpectedDirectPlaySystemMessageAssert;

// Compiler-emitted out-of-line copy of the MFC inline CPoint constructor used by
// resource-driven UI builders.
// LIBRARY: IMPERIALISM 0x00427100
// CPoint::CPoint

// CList<TView*, TView*> emissions for g_UiWidgetBuildStack.

// DirectPlay session manager object embedded at a fixed address (not a pointer).
// GLOBAL: IMPERIALISM 0x006a5f60
TWNetSessionManager g_NetworkSessionManager006a5f60;

// DirectPlay application identity written into DPSESSIONDESC2 before host/join enumeration.
// GLOBAL: IMPERIALISM 0x0066f968
const GUID g_ImperialismDirectPlayApplicationGuid = {
    0xc55dc2ef, 0xfd3e, 0x11d0, {0xbc, 0x16, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};

// GLOBAL: IMPERIALISM 0x006a15e0
CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_RuntimeSelectionRecords;

// Compiler-emitted methods for this TU's RuntimeSelectionRecord pointer-array
// specialization. The source implementation is the retail MFC CArray template.

// GLOBAL: IMPERIALISM 0x006a6014
TNetMgr* g_pNetMgr = 0;

// GLOBAL: IMPERIALISM 0x006a18e0
TApplication* g_pApplication = 0;

// GLOBAL: IMPERIALISM 0x006a44b0
extern "C" void* g_pActiveCityDialogLegendSelectionOwner = 0;

// GLOBAL: IMPERIALISM 0x006a44b4
// 4-byte flag (written as a dword by TStatusButton::DoEvent); BOOL-style int.
int g_bCityDialogLegendSelectionInitialized = 0;

// GLOBAL: IMPERIALISM 0x0065c7f8
const int g_ShipOrderStatusStringIndexByResourceType[14] = {
    -1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7,
};

// Per-type horizontal source offset in TNavyRoster's 0xdba bitmap atlas.
// GLOBAL: IMPERIALISM 0x006985e8
const short g_ShipRosterAtlasHorizontalOffsetByResourceType[14] = {
    0, 0, 0, 0, 160, 0, 0, 320, 480, 640, 0, 800, 960, 1120,
};

// Palette entries used to color ocean-map previews by their owning nation tag.
// GLOBAL: IMPERIALISM 0x006985b8
unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24] = {
    0xf3, 0x2a, 0x25, 0x1d, 0xf6, 0x8c,
    0xbd, 0x0a, 0x0b, 0x0d, 0x29, 0xde,
    0xdf, 0xfa, 0x2c, 0x31, 0x33, 0x41,
    0x48, 0xd0, 0xcd, 0xce, 0xcf, static_cast<unsigned char>(g_pViewMgr->GetColor(0x32)),
};

// GLOBAL: IMPERIALISM 0x0069859c
const bool g_bDrawOceanRouteOverlay = true;
// GLOBAL: IMPERIALISM 0x006985ac
const bool g_bTransferOceanViewportToActiveSurface = true;
// GLOBAL: IMPERIALISM 0x006985b0
const bool g_bDrawOceanZoneLabels = true;
// GLOBAL: IMPERIALISM 0x006985b4
const bool g_bDrawOceanNationLabels = true;

// Border/transition colors paired with the owner-fill table immediately above.
// GLOBAL: IMPERIALISM 0x006985d0
unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24] = {
    0x15, 0x2d, 0x1e, 0x1c, 0x30, 0xae,
    0xca, 0x7d, 0x7d, 0x7d, 0x7d, 0xe2,
    0xe2, 0xe2, 0xe2, 0x51, 0x51, 0x51,
    0x51, 0xf0, 0xf0, 0xf0, 0xf0, static_cast<unsigned char>(g_pViewMgr->GetColor(0x3c)),
};

// GLOBAL: IMPERIALISM 0x006a590c
TInfoBarText* g_pCursorControlPanel = NULL;

// GLOBAL: IMPERIALISM 0x006a59e0
POINT g_ptControlStringModalMessage = {0, 0};

// GLOBAL: IMPERIALISM 0x006a1ab0
CPoint g_turnEventDialogAnchorPoint(0, 0);

// GLOBAL: IMPERIALISM 0x006a1ac0
CList<TWindow*, TWindow*> g_ModalViewStack;

// GLOBAL: IMPERIALISM 0x006a1a40
CList<TWindow*, TWindow*> g_LiveViewRegistry;

// Compiler-emitted members of the CList<TWindow*, TWindow*> specialization shared by the
// two registries above (vtable 0x0064b580). The source implementation is the retail MFC
// CList template.

// GLOBAL: IMPERIALISM 0x006a1b24
TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry = NULL;

// GLOBAL: IMPERIALISM 0x006a1d18
GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord = {0, {0, 0, 0, 0}};
// GLOBAL: IMPERIALISM 0x006a1dc0
GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord = NULL;
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

// GLOBAL: IMPERIALISM 0x006a23b4
bool g_bBattleReportMarkerBlinkPhase = false;
// GLOBAL: IMPERIALISM 0x006a23b8
int g_nBattleReportMarkerBlinkTicks = 0;
// GLOBAL: IMPERIALISM 0x006a2318
POINT g_ptArmyOrderModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a2288
POINT g_ptArmyValidationModalMessage = {0, 0};
// Modal-message placement used when no eligible secondary home-city tile exists.
// GLOBAL: IMPERIALISM 0x006a2c18
POINT g_ptCityInteriorMinisterModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a3180
POINT g_ptNationComparisonModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a5820
POINT g_ptTechItemModalMessage = {0, 0};
// Placement point for the formatted-error ("ERROR (...)") modal message dialog.
// GLOBAL: IMPERIALISM 0x006a5ab0
POINT g_ptFormattedErrorModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a3d08
POINT g_ptNationAwolModalMessage = {0, 0};
// Lounge host confirmation for replacing a remote nation with an AI.
// GLOBAL: IMPERIALISM 0x006a3d98
POINT g_ptLoungeNationReplacementModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a45c0
POINT g_ptMapModeModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a4650
POINT g_ptTacticalAutoPlayModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a57c8
POINT g_ptTechCapabilityModalMessage = {0, 0};
// Modal-message placement point used by the TViewMgr prompt helpers (0x5de990/0x5deb40).
// GLOBAL: IMPERIALISM 0x006a5be0
POINT g_ptUiPromptModalMessage = {0, 0};
// City-site selection warning placement and TViewMgr's initial dialog-placement seed.
// GLOBAL: IMPERIALISM 0x006a5b58
POINT g_ptCitySiteSelectionDialogPlacement = {0, 0};
// GLOBAL: IMPERIALISM 0x006a4048
POINT g_ptQueryFloaterModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a2fc0
POINT g_ptDiplomacyNoticeModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a4218
POINT g_ptGameSetupModalMessage = {0, 0};

// GLOBAL: IMPERIALISM 0x006a31c0
int g_lastTurnAlertTick = 0;

// GLOBAL: IMPERIALISM 0x006a4608
int g_lastClickedMapTileIndex = 0;

// GLOBAL: IMPERIALISM 0x006a5bac
int g_nationInfoGoldResourceOverride = 0;

// GLOBAL: IMPERIALISM 0x006a5bb0
int g_nViewMgrModalAssertGate = 0;

// GLOBAL: IMPERIALISM 0x006a60f8
int g_localizationAudioSlotCursor = 0;

// GLOBAL: IMPERIALISM 0x006a475c
TTacticalBattle* g_pActiveTacticalBattle;

// OR-accumulator for the turn-event-0x2b presence-mask exchange.
// GLOBAL: IMPERIALISM 0x006a3d64
int g_nTurnEvent2BNationMaskAccumulator;

// GLOBAL: IMPERIALISM 0x006955f0
int g_anWeightedNeighborUnitScoreByType[32] = {
    70,  137, 135, 164, 165, 211,  193, 300, 95,  243, 230, 265, 230, 275, 323, 549,
    170, 450, 471, 495, 493, 1010, 715, 913, 193, 260, 360, 200, 200, 200, 0,   1000,
};

// GLOBAL: IMPERIALISM 0x00669858
short g_anUnitTypeCombatCategoryByType[32] = {0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2,
                                              0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// GLOBAL: IMPERIALISM 0x00669898
short g_awUnitTypeBaseActionPointTable[32] = {40, 60,  40, 40, 110, 90, 50, 30, 40, 60,  40,
                                              40, 110, 90, 60, 30,  50, 70, 50, 40, 110, 90,
                                              80, 30,  40, 40, 50,  90, 90, 90, 0,  0};

// GLOBAL: IMPERIALISM 0x006994c0
TacticalTileHeuristicScorerFn g_apfnTacticalTileHeuristicScorers[15] = {
    &TArmyPlayer::FactorStayPut,                              // [0]  0x59d6b0
    &TArmyPlayer::FactorTargetEnemy,                          // [1]  0x59d6e0
    &TArmyPlayer::FactorSapFort,                              // [2]  0x59d810
    &TArmyPlayer::FactorMeleeEnemy,                           // [3]  0x59d8a0
    &TArmyPlayer::FactorEnemyFire,                            // [4]  0x59d940
    &TArmyPlayer::FactorRetreat,                              // [5]  0x59da20
    &TArmyPlayer::FactorRoughTerrain,                         // [6]  0x59dac0
    &TArmyPlayer::FactorNearCowards,                          // [7]  0x59db00
    &TArmyPlayer::ScoreTacticalTileDistanceFieldAdvance,      // [8]  0x59dba0
    &TArmyPlayer::ScoreTacticalTileFriendlyArtillerySpacing,  // [9]  0x59dbe0
    &TArmyPlayer::ScoreTacticalTileArtilleryFiringLaneColumn, // [10] 0x59dcd0
    &TArmyPlayer::FactorHitByArty,                            // [11] 0x59dd40
    &TArmyPlayer::FactorTargetMaxRange,                       // [12] 0x59de30
    &TArmyPlayer::FactorHitEnemyArtillery,                    // [13] 0x59dfe0
    &TArmyPlayer::ScoreTacticalTileEnemyEdgeColumnZoneBonus,  // [14] 0x59e0d0
};

// Tactical AI cursor-mode ratio thresholds and projection factors (.rdata FP pool).
// GLOBAL: IMPERIALISM 0x00669508
double g_dTacticalCursorStrongRatioThreshold = 3.0;
// GLOBAL: IMPERIALISM 0x00669510
double g_dTacticalCursorOverwhelmRatioThreshold = 4.0;
// GLOBAL: IMPERIALISM 0x00669518
double g_dTacticalCursorWeakRatioThreshold = 0.25;
// GLOBAL: IMPERIALISM 0x00669520
double g_dTacticalCursorArtilleryParityThreshold = 1.0;
// GLOBAL: IMPERIALISM 0x00669528
double g_dTacticalCursorArtillerySuperiorityThreshold = 1.8;
// GLOBAL: IMPERIALISM 0x00669530
double g_dTacticalCursorAssaultRatioThreshold = 2.5;
// GLOBAL: IMPERIALISM 0x00669538
double g_dTacticalCursorRetreatRatioThreshold = 0.8;
// GLOBAL: IMPERIALISM 0x00669ec0
float g_fTacticalRetreatQualityWeightDefault = 0.0f;
// GLOBAL: IMPERIALISM 0x00669ec8
double g_dTacticalQualityFactorStep = -0.1;
// GLOBAL: IMPERIALISM 0x00669ed0
double g_dTacticalQualityFactorBase = 1.0;
// GLOBAL: IMPERIALISM 0x00669f0c
float g_fTacticalStrengthProjectionScale = 0.002f;

// GLOBAL: IMPERIALISM 0x00669390
float g_afTacticalDirectFireFlagByCategoryCode[10] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f,
                                                      1.0f, 0.0f, 0.0f, 1.0f, 1.0f};

// GLOBAL: IMPERIALISM 0x006693b8
short g_awTacticalUnitAiClassByUnitType[32] = {0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2,
                                               0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// GLOBAL: IMPERIALISM 0x006693f8
short g_awTacticalUnitActionPointCostByType[32] = {40, 60,  40, 40, 110, 90, 50, 30, 40, 60,  40,
                                                   40, 110, 90, 60, 30,  50, 70, 50, 40, 110, 90,
                                                   80, 30,  40, 40, 50,  90, 90, 90, 0,  0};

// GLOBAL: IMPERIALISM 0x00699500
int g_anTacticalTileHeuristicWeightsByAiState[20][15] = {
    {1, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0},
    {0, 100, 0, 200, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, -10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 100, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 100, 0, 200, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 100, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, -1, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, -1, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},
    {1, 0, 0, 100, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 200, 0, 0, 0},
    {0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
    {0, 1, 0, 0, -100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};

// GLOBAL: IMPERIALISM 0x00669830
float g_afTacticalDirectFireFlagByCategory[10] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f,
                                                  1.0f, 0.0f, 0.0f, 1.0f, 1.0f};

// Base attack power per unit type (.rdata floats).
// GLOBAL: IMPERIALISM 0x006698d8
float g_afTacticalBaseAttackPowerByUnitType[30] = {
    50.0f,  50.0f,  100.0f, 125.0f, 75.0f,  150.0f, 100.0f, 160.0f, 75.0f,  100.0f,
    150.0f, 175.0f, 100.0f, 200.0f, 175.0f, 300.0f, 100.0f, 150.0f, 225.0f, 250.0f,
    225.0f, 450.0f, 250.0f, 500.0f, 0.0f,   0.0f,   0.0f,   0.0f,   0.0f,   0.0f};

// Melee (adjacent-attack) power multiplier per unit category (.rdata floats).
// GLOBAL: IMPERIALISM 0x00669950
float g_afTacticalMeleeMultiplierByCategory[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.3f, 1.3f, 0.2f, 0.2f};

// Incoming-damage scale per defender unit type (.rdata floats).
// GLOBAL: IMPERIALISM 0x00669970
float g_afTacticalDamageScaleByUnitType[30] = {
    0.0025f, 0.0015f, 0.002f,  0.002f,  0.0015f, 0.002f,  0.004f, 0.005f,  0.0025f, 0.0015f,
    0.0015f, 0.0015f, 0.0015f, 0.002f,  0.003f,  0.0035f, 0.001f, 0.0005f, 0.0005f, 0.0005f,
    0.001f,  0.0005f, 0.0005f, 0.0005f, 0.003f,  0.0025f, 0.001f, 0.002f,  0.0015f, 0.0005f};

// Incoming-damage scale per defender navy unit type (.rdata floats).
// GLOBAL: IMPERIALISM 0x00669d28
float g_afTacticalNavyDamageScaleByUnitType[8] = {0.045f, 0.04f,  0.04f,  0.022f,
                                                  0.02f,  0.025f, 0.015f, 0.022f};

// Base attack power per navy unit type (.rdata floats).
// GLOBAL: IMPERIALISM 0x00669d48
float g_afTacticalNavyBaseAttackPowerByUnitType[8] = {3.0f, 3.5f, 4.0f,  4.0f,
                                                      8.0f, 8.0f, 15.0f, 15.0f};

// GLOBAL: IMPERIALISM 0x00669d68
int g_anNavyTacticalMoveCostsByDirection[6] = {15, 10, 20, 40, 20, 10};

// GLOBAL: IMPERIALISM 0x00669d80
int g_anTacticalNavyUnitTypeByShipType[14] = {-1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7};

// Attack-power terrain modifier [category * 5 + tile terrainType] (.rdata floats).
// GLOBAL: IMPERIALISM 0x00669ac8
float g_afTacticalAttackTerrainModifierByCategory[50] = {
    1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  1.0f,  1.0f,  1.0f,  0.0f, 1.0f,  0.75f, 0.75f,
    1.0f,  0.0f,  1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  1.0f,  1.0f, 1.0f,  0.0f,  1.0f,
    0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f, 0.75f, 0.75f, 1.0f,
    0.0f,  1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  0.75f, 0.75f, 1.0f, 0.0f};

// Incoming-damage terrain modifier [defender category * 5 + terrainType] (.rdata).
// GLOBAL: IMPERIALISM 0x00669b90
float g_afTacticalDefenseTerrainModifierByCategory[50] = {
    1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 0.8f, 0.8f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f,
    1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f,
    1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f,
    0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f};

// GLOBAL: IMPERIALISM 0x00669c58
float g_afTacticalCoverDamageModifierByCategory[50] = {
    1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f,
    0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 1.0f, 0.7f, 0.6f, 0.5f, 1.0f,
    1.0f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f,
    0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f};

// GLOBAL: IMPERIALISM 0x00669a60
short g_awTacticalMoveCostByCategoryAndTerrain[50] = {
    10,  20, 30,  15, 999, 10,  10, 10,  10, 999, 10,  20, 30,  15, 999, 10, 20,
    30,  15, 999, 10, 10,  10,  10, 999, 10, 20,  30,  15, 999, 10, 20,  30, 15,
    999, 10, 20,  30, 15,  999, 10, 20,  30, 15,  999, 10, 20,  30, 15,  999};

// GLOBAL: IMPERIALISM 0x00669818
int g_anFortStrengthPointsByFortLevel[6] = {0, 0, 500, 750, 1000, 0};

// Battle-setup terrain layout file-name template ("data/%%03d.tab").
// GLOBAL: IMPERIALISM 0x00699e20
extern "C" const char g_szBattleSetupTabPathFormat[] = "data/%03d.tab";

// Source-path string for UTacPlayer.cpp asserts.
// GLOBAL: IMPERIALISM 0x00699d84
extern "C" const char s_SourcePathUTacPlayer[] = "D:\\Ambit\\Cross\\UTacPlayer.cpp";

// GLOBAL: IMPERIALISM 0x00669db8
const char* g_pszEmptyTextRef = g_szEmptyString;

// Paragraph separator between the two per-side casualty lines of the battle summary.
// GLOBAL: IMPERIALISM 0x00699438
extern "C" const char s_szDoubleNewline[] = "\n\n";

// GLOBAL: IMPERIALISM 0x00669dc0
short g_awTacticalFireSfxTokenByUnitType[32] = {
    0x3a98, 0x3a98, 0x3a98, 0x3a98, 0x3a99, 0x3a99, 0x3a9b, 0x3a9b, 0x3a98, 0x3a98, 0x3a98,
    0x3a98, 0x3a99, 0x3a99, 0x3a9b, 0x3a9b, 0x3aa6, 0x3aa6, 0x3aa6, 0x3a9c, 0x3aa6, 0x3a9a,
    0x3a9b, 0x3a9b, 0x3a9d, 0x3a9d, 0x3a9d, 0x3a98, 0x3a98, 0x3aa6, 0,      0};

// GLOBAL: IMPERIALISM 0x006a4758
bool g_nForceTacticalBattleViewFlag;

// Save-game path construction strings.
// GLOBAL: IMPERIALISM 0x00698708
char g_szImpSaveExtension[] = ".imp";
// GLOBAL: IMPERIALISM 0x00698710
char g_szMultiplayerSavePrefix[] = "mult";
// GLOBAL: IMPERIALISM 0x00698718
char g_szSingleSlotSavePrefix[] = "slot";
// GLOBAL: IMPERIALISM 0x00698720
char g_szLiteralRb[] = "rb";
// GLOBAL: IMPERIALISM 0x00698724
char g_szSaveDirectoryPrefix[] = "Save/";
// GLOBAL: IMPERIALISM 0x0069872c
char g_szLiteralA[] = "A";
// GLOBAL: IMPERIALISM 0x0069b848
char g_szSavedDocumentMarker[] = "__saved";
// GLOBAL: IMPERIALISM 0x0069b854
char g_szLoadedDocumentMarker[] = "__loaded";
// GLOBAL: IMPERIALISM 0x0065ddd0
const char* const g_pszSingleSlotSavePrefix = g_szSingleSlotSavePrefix;
// GLOBAL: IMPERIALISM 0x0065ddd4
const char* const g_pszMultiplayerSavePrefix = g_szMultiplayerSavePrefix;
// GLOBAL: IMPERIALISM 0x0065ddd8
const char* const g_pszImpSaveExtension = g_szImpSaveExtension;
// GLOBAL: IMPERIALISM 0x00697cbc
char g_szClientSavePrefix[] = "cli_";
// GLOBAL: IMPERIALISM 0x0065bf5c
const char* const g_pszClientSavePrefix = g_szClientSavePrefix;
// GLOBAL: IMPERIALISM 0x006a2178
char g_ScenarioSaveNameBuffer[0x30];
// Modal placement used for invalid/cross-session save-file warnings.
// GLOBAL: IMPERIALISM 0x006a2128
POINT g_ptSaveLoadErrorModalMessage = {0, 0};
// One-shot guard for TAmbitFileBasedDocument::SaveDocument's UAmbit.cpp assertion.
// GLOBAL: IMPERIALISM 0x006a21c4
int g_saveDocumentAssertGuard = 0;
// Default text returned for a null nation descriptor (points at g_szEmptyString).
// GLOBAL: IMPERIALISM 0x00653300
char* g_pszDescriptorDefaultName = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x006973c8
char g_szUiCloseParen[] = ")";
// GLOBAL: IMPERIALISM 0x0069806c
char g_szUiOpenParen[] = "(";
// GLOBAL: IMPERIALISM 0x006a2d40
POINT g_ptCivilianOrderModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a2df0
POINT g_ptGreatPowerModalMessage = {0, 0};
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

// GLOBAL: IMPERIALISM 0x006a3478
SeapointStretch g_seapointQuadTable;
// GLOBAL: IMPERIALISM 0x006a3498
int g_cityRegionIdRemapTable[0x100];
// GLOBAL: IMPERIALISM 0x006a3900
SeaSegmentStretch g_regionBorderLinkTable;

const int g_anTechItemPurchaseCostBySlot[34] = {
    0,     0,      1000,   1000,   1500,   1500,  1500,  1500,  3000,  3000,  3000,  6000,
    7000,  10000,  12000,  12000,  12000,  12000, 12000, 25000, 20000, 40000, 40000, 40000,
    40000, 100000, 120000, 150000, 150000, 0,     -1,    -1,    -1,    0};

// Hex-neighbour offset tables (direction 0..5) for the 108-wide offset-coordinate grid.
const int g_hexColOffsetEvenRow[6] = {0, 1, 0, -1, -1, -1};
const int g_hexRowOffset[6] = {-1, 0, 1, 1, 0, -1};
const int g_hexColOffsetOddRow[6] = {1, 1, 1, 0, -1, 0};

// GLOBAL: IMPERIALISM 0x00697498
const int g_coarseHexColOffsetEvenRow[6] = {1, 1, 1, 0, -1, 0};
// GLOBAL: IMPERIALISM 0x006974b0
const int g_coarseHexRowOffset[6] = {-1, 0, 1, 1, 0, -1};
// GLOBAL: IMPERIALISM 0x006974c8
const int g_coarseHexColOffsetOddRow[6] = {0, 1, 0, -1, -1, -1};

// GLOBAL: IMPERIALISM 0x00697568
const int g_riverConnectionTypeByDirectionPair[6][6] = {{0, 0, 1, 2, 3, 0}, {0, 0, 0, 4, 5, 6},
                                                        {1, 0, 0, 0, 7, 8}, {2, 4, 0, 0, 0, 9},
                                                        {3, 5, 7, 0, 0, 0}, {0, 6, 8, 9, 0, 0}};

// GLOBAL: IMPERIALISM 0x00696e40
const unsigned short g_hexDirectionBitMasks[6] = {1, 2, 4, 8, 16, 32};

// GLOBAL: IMPERIALISM 0x00696ea8
const unsigned short g_hexDirectionBitMasksAlt[7] = {1, 2, 4, 8, 16, 32, 0};
// GLOBAL: IMPERIALISM 0x00696eb8
const short g_railDirectionAddMasks[6] = {1, 2, 4, 8, 16, 32};
// GLOBAL: IMPERIALISM 0x00696ec8
const short g_railDirectionSubtractMasks[6] = {1, 2, 4, 8, 16, 32};

// Map-generation PRNG state + region-seed grid dimensions, runtime-initialized to 0.
// GLOBAL: IMPERIALISM 0x006a38e8
unsigned int g_mapGenLcgState = 0;
// GLOBAL: IMPERIALISM 0x006a38ec
int g_regionSeedGridRows = 0;
// GLOBAL: IMPERIALISM 0x006a38f0
int g_regionSeedGridCols = 0;
// GLOBAL: IMPERIALISM 0x006a38bc
int g_mapGenDesertQuota = 0;
// GLOBAL: IMPERIALISM 0x006a3470
int g_mapGenMountainQuota = 0;
// GLOBAL: IMPERIALISM 0x006a38c0
int g_mapGenHillsQuota = 0;
// GLOBAL: IMPERIALISM 0x006a38f8
int g_mapGenForestQuota = 0;
// GLOBAL: IMPERIALISM 0x006a38e0
int g_mapGenSwampQuota = 0;
// Map-gen feature count set alongside the quotas (default 10; tuning 'm' = 20, 'p' = 5).
// GLOBAL: IMPERIALISM 0x006a38e4
int g_mapGenRiverCount = 0;

// One-shot assert-suppression flags for the UMapper overlay passes (0x006a3910/0x006a3914).
int g_bOverlayScanlineFillAssertSuppressed = 0;
int g_bOverlayRouteRebuildAssertSuppressed = 0;

// GLOBAL: IMPERIALISM 0x006a1a10
int g_streamLine304AssertGuard = 0;
// GLOBAL: IMPERIALISM 0x006a1a14
int g_streamLine596AssertGuard = 0;

// GLOBAL: IMPERIALISM 0x006a5aec
unsigned int g_zoneStatusCodePrngSeed = GetTickCountDiv16();
// GLOBAL: IMPERIALISM 0x006a5af0
extern "C" short g_anProvinceNameOrdinalByNationSlot[23] = {0};
// GLOBAL: IMPERIALISM 0x006984b8 (static init -1 in the original .data section)
int g_mapActionContextDisplayNameCacheId = -1;
// GLOBAL: IMPERIALISM 0x006984bc (static init 7 in the original .data section)
int g_mapActionContextDisplayNameCacheStep = 7;

// GLOBAL: IMPERIALISM 0x00695794
char s_szSpaceSeparator[] = " ";
// GLOBAL: IMPERIALISM 0x0069936c
char s_szGaugeCountSeparator[] = "  /  ";
// Six-space indent prefixed to each great-power turn-summary line (0x4e2b70).
// GLOBAL: IMPERIALISM 0x00696790
char s_szTurnSummaryIndent[] = "      ";
// GLOBAL: IMPERIALISM 0x00695844
extern const char g_szGarrisonSecretNationNameFrog[] = "Frog";
// GLOBAL: IMPERIALISM 0x0069584c
extern const char g_szGarrisonSecretUnitNameSnidely[] = "Snidely";
// GLOBAL: IMPERIALISM 0x00695880
extern "C" const char s_szLineBreak[8] = {'\n', 0, 0, 0, 'T', 'B', 'a', 't'};
// GLOBAL: IMPERIALISM 0x00699320
char s_szTurnHistorySeparator[8] = {':', ' ', 0, 0, 'L', 'o', 's', 's'};
// GLOBAL: IMPERIALISM 0x00699324
char s_szCombatLossesHeading[] = "Losses\n";
// GLOBAL: IMPERIALISM 0x006993e8
bool g_applyMiniMapVerticalClipOffset = true;
// GLOBAL: IMPERIALISM 0x0069b71c
char s_szTurnHistoryPrefix[] = "Turn ";
// GLOBAL: IMPERIALISM 0x0069578c
char s_szAdmiralPrefix[] = "Adm. ";
// GLOBAL: IMPERIALISM 0x00696b10
char s_szColonSeparator[] = ":";
// GLOBAL: IMPERIALISM 0x00696674
char s_mcflavor_00696674[] = "X";
// GLOBAL: IMPERIALISM 0x00696d10
char s_mcflavor_00696d10[] = "r";
// GLOBAL: IMPERIALISM 0x00697238
char s_mcflavor_00697238[] = "w";
// Script-dump format strings for TMapMgr::DumpAndResetMapScriptState (0x519140).
// GLOBAL: IMPERIALISM 0x006972f8
char g_szScriptFileName[] = "script";
// GLOBAL: IMPERIALISM 0x006972e8
char g_szFmtZone[] = "zone %d %s\n";
// GLOBAL: IMPERIALISM 0x006972d0
char g_szFmtShip[] = "ship %d %d %d %d\n";
// GLOBAL: IMPERIALISM 0x006972bc
char g_szFmtArmy[] = "army %d %d %d\n";
// GLOBAL: IMPERIALISM 0x006972ac
char g_szFmtCivi[] = "civi %d %d\n";
// GLOBAL: IMPERIALISM 0x006972a0
char g_szFmtPort[12] = "port %d\n";
// GLOBAL: IMPERIALISM 0x00697294
char g_szFmtRail[12] = "rail %d\n";
// GLOBAL: IMPERIALISM 0x00697280
char g_szFmtCapa[] = "capa %d %d %d\n";
// GLOBAL: IMPERIALISM 0x00697268
char g_szFmtLabo[] = "labo %d %d %d %d\n";
// GLOBAL: IMPERIALISM 0x00697254
char g_szFmtEmba[] = "emba %d %d %d\n";
// GLOBAL: IMPERIALISM 0x00697248
char g_szFmtYear[12] = "year %d\n";
// GLOBAL: IMPERIALISM 0x006976e0
char g_szLiteralWb[] = "wb";
// GLOBAL: IMPERIALISM 0x00698b0c
char g_szLowercaseX[] = "x";
// GLOBAL: IMPERIALISM 0x0069ab00
char s_mcflavor_0069ab00[] = "ie";
// GLOBAL: IMPERIALISM 0x0069ab04
char s_mcflavor_0069ab04[] = "\366";
// GLOBAL: IMPERIALISM 0x0069ab08
char s_mcflavor_0069ab08[] = "au";
// GLOBAL: IMPERIALISM 0x0069ab0c
char s_mcflavor_0069ab0c[] = "eu";
// GLOBAL: IMPERIALISM 0x0069ab10
char s_mcflavor_0069ab10[] = "\344";
// GLOBAL: IMPERIALISM 0x0069ab14
char s_mcflavor_0069ab14[] = "ei";
// GLOBAL: IMPERIALISM 0x0069ab18
char s_mcflavor_0069ab18[] = "o";
// GLOBAL: IMPERIALISM 0x0069ab1c
char s_mcflavor_0069ab1c[] = "\374";
// GLOBAL: IMPERIALISM 0x0069ab20
char s_mcflavor_0069ab20[] = "i";
// GLOBAL: IMPERIALISM 0x0069ab24
char s_mcflavor_0069ab24[] = "e";
// GLOBAL: IMPERIALISM 0x0069ab28
char s_mcflavor_0069ab28[] = "u";
// GLOBAL: IMPERIALISM 0x0069ab2c
char s_mcflavor_0069ab2c[] = "a";
// GLOBAL: IMPERIALISM 0x0069ab30
char s_mcflavor_0069ab30[] = "ck";
// GLOBAL: IMPERIALISM 0x0069ab34
char s_mcflavor_0069ab34[] = "ln";
// GLOBAL: IMPERIALISM 0x0069ab38
char s_mcflavor_0069ab38[] = "nz";
// GLOBAL: IMPERIALISM 0x0069ab3c
char s_mcflavor_0069ab3c[] = "ch";
// GLOBAL: IMPERIALISM 0x0069ab40
char s_mcflavor_0069ab40[] = "l";
// GLOBAL: IMPERIALISM 0x0069ab44
char s_mcflavor_0069ab44[] = "dt";
// GLOBAL: IMPERIALISM 0x0069ab48
char s_mcflavor_0069ab48[] = "m";
// GLOBAL: IMPERIALISM 0x0069ab4c
char s_mcflavor_0069ab4c[] = "rf";
// GLOBAL: IMPERIALISM 0x0069ab50
char s_mcflavor_0069ab50[] = "rt";
// GLOBAL: IMPERIALISM 0x0069ab54
char s_mcflavor_0069ab54[] = "rg";
// GLOBAL: IMPERIALISM 0x0069ab58
char s_mcflavor_0069ab58[] = "rst";
// GLOBAL: IMPERIALISM 0x0069ab5c
char s_mcflavor_0069ab5c[] = "tt";
// GLOBAL: IMPERIALISM 0x0069ab60
char s_mcflavor_0069ab60[] = "nch";
// GLOBAL: IMPERIALISM 0x0069ab64
char s_mcflavor_0069ab64[] = "gb";
// GLOBAL: IMPERIALISM 0x0069ab68
char s_mcflavor_0069ab68[] = "bl";
// GLOBAL: IMPERIALISM 0x0069ab6c
char s_mcflavor_0069ab6c[] = "tzn";
// GLOBAL: IMPERIALISM 0x0069ab70
char s_mcflavor_0069ab70[] = "n";
// GLOBAL: IMPERIALISM 0x0069ab74
char s_mcflavor_0069ab74[] = "tzl";
// GLOBAL: IMPERIALISM 0x0069ab78
char s_mcflavor_0069ab78[] = "sb";
// GLOBAL: IMPERIALISM 0x0069ab7c
char s_mcflavor_0069ab7c[] = "sl";
// GLOBAL: IMPERIALISM 0x0069ab80
char s_mcflavor_0069ab80[] = "ssl";
// GLOBAL: IMPERIALISM 0x0069ab84
char s_mcflavor_0069ab84[] = "pp";
// GLOBAL: IMPERIALISM 0x0069ab88
char s_mcflavor_0069ab88[] = "nnh";
// GLOBAL: IMPERIALISM 0x0069ab8c
char s_mcflavor_0069ab8c[] = "ffh";
// GLOBAL: IMPERIALISM 0x0069ab90
char s_mcflavor_0069ab90[] = "st";
// GLOBAL: IMPERIALISM 0x0069ab94
char s_mcflavor_0069ab94[] = "ttw";
// GLOBAL: IMPERIALISM 0x0069ab98
char s_mcflavor_0069ab98[] = "ll";
// GLOBAL: IMPERIALISM 0x0069ab9c
char s_mcflavor_0069ab9c[] = "b";
// GLOBAL: IMPERIALISM 0x0069aba0
char s_mcflavor_0069aba0[] = "lb";
// GLOBAL: IMPERIALISM 0x0069aba4
char s_mcflavor_0069aba4[] = "d";
// GLOBAL: IMPERIALISM 0x0069aba8
char s_mcflavor_0069aba8[] = "nb";
// GLOBAL: IMPERIALISM 0x0069abac
char s_mcflavor_0069abac[] = "\337";
// GLOBAL: IMPERIALISM 0x0069abb0
char s_mcflavor_0069abb0[] = "nsb";
// GLOBAL: IMPERIALISM 0x0069abb4
char s_mcflavor_0069abb4[] = "g";
// GLOBAL: IMPERIALISM 0x0069abb8
char s_mcflavor_0069abb8[] = "nd";
// GLOBAL: IMPERIALISM 0x0069abbc
char s_mcflavor_0069abbc[] = "lst";
// GLOBAL: IMPERIALISM 0x0069abc0
char s_mcflavor_0069abc0[] = "ng";
// GLOBAL: IMPERIALISM 0x0069abc4
char s_mcflavor_0069abc4[] = "chst";
// GLOBAL: IMPERIALISM 0x0069abcc
char s_mcflavor_0069abcc[] = "nh";
// GLOBAL: IMPERIALISM 0x0069abd0
char s_mcflavor_0069abd0[] = "s";
// GLOBAL: IMPERIALISM 0x0069abd4
char s_mcflavor_0069abd4[] = "rch";
// GLOBAL: IMPERIALISM 0x0069abd8
char s_mcflavor_0069abd8[] = "rrk";
// GLOBAL: IMPERIALISM 0x0069abdc
char s_mcflavor_0069abdc[] = "hld";
// GLOBAL: IMPERIALISM 0x0069abe0
char s_mcflavor_0069abe0[] = "ss";
// GLOBAL: IMPERIALISM 0x0069abe4
char s_mcflavor_0069abe4[] = "ttg";
// GLOBAL: IMPERIALISM 0x0069abe8
char s_mcflavor_0069abe8[] = "gsb";
// GLOBAL: IMPERIALISM 0x0069abec
char s_mcflavor_0069abec[] = "nkf";
// GLOBAL: IMPERIALISM 0x0069abf0
char s_mcflavor_0069abf0[] = "rl";
// GLOBAL: IMPERIALISM 0x0069abf4
char s_mcflavor_0069abf4[] = "mb";
// GLOBAL: IMPERIALISM 0x0069abf8
char s_mcflavor_0069abf8[] = "E";
// GLOBAL: IMPERIALISM 0x0069abfc
char s_mcflavor_0069abfc[] = "\334";
// GLOBAL: IMPERIALISM 0x0069ac00
char s_mcflavor_0069ac00[] = "I";
// GLOBAL: IMPERIALISM 0x0069ac04
char s_mcflavor_0069ac04[] = "Ei";
// GLOBAL: IMPERIALISM 0x0069ac08
char s_mcflavor_0069ac08[] = "Au";
// GLOBAL: IMPERIALISM 0x0069ac0c
char s_mcflavor_0069ac0c[] = "D";
// GLOBAL: IMPERIALISM 0x0069ac10
char s_mcflavor_0069ac10[] = "S";
// GLOBAL: IMPERIALISM 0x0069ac14
char s_mcflavor_0069ac14[] = "K";
// GLOBAL: IMPERIALISM 0x0069ac18
char s_mcflavor_0069ac18[] = "Kr";
// GLOBAL: IMPERIALISM 0x0069ac1c
char s_mcflavor_0069ac1c[] = "G";
// GLOBAL: IMPERIALISM 0x0069ac20
char s_mcflavor_0069ac20[] = "Sch";
// GLOBAL: IMPERIALISM 0x0069ac24
char s_mcflavor_0069ac24[] = "N";
// GLOBAL: IMPERIALISM 0x0069ac28
char s_mcflavor_0069ac28[] = "V";
// GLOBAL: IMPERIALISM 0x0069ac2c
char s_mcflavor_0069ac2c[] = "W";
// GLOBAL: IMPERIALISM 0x0069ac30
char s_mcflavor_0069ac30[] = "Schw";
// GLOBAL: IMPERIALISM 0x0069ac38
char s_mcflavor_0069ac38[] = "R";
// GLOBAL: IMPERIALISM 0x0069ac3c
char s_mcflavor_0069ac3c[] = "Pf";
// GLOBAL: IMPERIALISM 0x0069ac40
char s_mcflavor_0069ac40[] = "P";
// GLOBAL: IMPERIALISM 0x0069ac44
char s_mcflavor_0069ac44[] = "M";
// GLOBAL: IMPERIALISM 0x0069ac48
char s_mcflavor_0069ac48[] = "F";
// GLOBAL: IMPERIALISM 0x0069ac4c
char s_mcflavor_0069ac4c[] = "St";
// GLOBAL: IMPERIALISM 0x0069ac50
char s_mcflavor_0069ac50[] = "Fr";
// GLOBAL: IMPERIALISM 0x0069ac54
char s_mcflavor_0069ac54[] = "B";
// GLOBAL: IMPERIALISM 0x0069ac58
char s_mcflavor_0069ac58[] = "H";
// GLOBAL: IMPERIALISM 0x0069ac5c
char s_mcflavor_0069ac5c[] = "Kvl";
// GLOBAL: IMPERIALISM 0x0069ac60
char s_mcflavor_0069ac60[] = "Vkvkvkvl";
// GLOBAL: IMPERIALISM 0x0069ac6c
char s_mcflavor_0069ac6c[] = "Vkvkvl";
// GLOBAL: IMPERIALISM 0x0069ac74
char s_mcflavor_0069ac74[] = "Kvkvkvl";
// GLOBAL: IMPERIALISM 0x0069ac80
char s_mcflavor_0069ac80[] = "Kvkw";
// GLOBAL: IMPERIALISM 0x0069ac88
char s_mcflavor_0069ac88[] = "Vkvl";
// GLOBAL: IMPERIALISM 0x0069ac90
char s_mcflavor_0069ac90[] = "Kvkvl";
// GLOBAL: IMPERIALISM 0x0069ac98
char s_mcflavor_0069ac98[] = "ai";
// GLOBAL: IMPERIALISM 0x0069ac9c
char s_mcflavor_0069ac9c[] = "ia";
// GLOBAL: IMPERIALISM 0x0069aca0
char s_mcflavor_0069aca0[] = "aiu";
// GLOBAL: IMPERIALISM 0x0069aca4
char s_mcflavor_0069aca4[] = "eio";
// GLOBAL: IMPERIALISM 0x0069aca8
char s_mcflavor_0069aca8[] = "io";
// GLOBAL: IMPERIALISM 0x0069acac
char s_mcflavor_0069acac[] = "ndr";
// GLOBAL: IMPERIALISM 0x0069acb0
char s_mcflavor_0069acb0[] = "thr";
// GLOBAL: IMPERIALISM 0x0069acb4
char s_mcflavor_0069acb4[] = "fn";
// GLOBAL: IMPERIALISM 0x0069acb8
char s_mcflavor_0069acb8[] = "sv";
// GLOBAL: IMPERIALISM 0x0069acbc
char s_mcflavor_0069acbc[] = "f";
// GLOBAL: IMPERIALISM 0x0069acc0
char s_mcflavor_0069acc0[] = "rk";
// GLOBAL: IMPERIALISM 0x0069acc4
char s_mcflavor_0069acc4[] = "sp";
// GLOBAL: IMPERIALISM 0x0069acc8
char s_mcflavor_0069acc8[] = "p";
// GLOBAL: IMPERIALISM 0x0069accc
char s_mcflavor_0069accc[] = "str";
// GLOBAL: IMPERIALISM 0x0069acd0
char s_mcflavor_0069acd0[] = "mn";
// GLOBAL: IMPERIALISM 0x0069acd4
char s_mcflavor_0069acd4[] = "kl";
// GLOBAL: IMPERIALISM 0x0069acd8
char s_mcflavor_0069acd8[] = "nn";
// GLOBAL: IMPERIALISM 0x0069acdc
char s_mcflavor_0069acdc[] = "nth";
// GLOBAL: IMPERIALISM 0x0069ace0
char s_mcflavor_0069ace0[] = "th";
// GLOBAL: IMPERIALISM 0x0069ace4
char s_mcflavor_0069ace4[] = "k";
// GLOBAL: IMPERIALISM 0x0069ace8
char s_mcflavor_0069ace8[] = "Ioa";
// GLOBAL: IMPERIALISM 0x0069acec
char s_mcflavor_0069acec[] = "T";
// GLOBAL: IMPERIALISM 0x0069acf0
char s_mcflavor_0069acf0[] = "Z";
// GLOBAL: IMPERIALISM 0x0069acf4
char s_mcflavor_0069acf4[] = "Tr";
// GLOBAL: IMPERIALISM 0x0069acf8
char s_mcflavor_0069acf8[] = "Sp";
// GLOBAL: IMPERIALISM 0x0069acfc
char s_mcflavor_0069acfc[] = "Kh";
// GLOBAL: IMPERIALISM 0x0069ad00
char s_mcflavor_0069ad00[] = "Th";
// GLOBAL: IMPERIALISM 0x0069ad04
char s_mcflavor_0069ad04[] = "Kvkvkw";
// GLOBAL: IMPERIALISM 0x0069ad0c
char s_mcflavor_0069ad0c[] = "Vkvkw";
// GLOBAL: IMPERIALISM 0x0069ad14
char s_mcflavor_0069ad14[] = "Kvkvkvkw";
// GLOBAL: IMPERIALISM 0x0069ad20
char s_mcflavor_0069ad20[] = "oa";
// GLOBAL: IMPERIALISM 0x0069ad24
char s_mcflavor_0069ad24[] = "ua";
// GLOBAL: IMPERIALISM 0x0069ad28
char s_mcflavor_0069ad28[] = "oi";
// GLOBAL: IMPERIALISM 0x0069ad2c
char s_mcflavor_0069ad2c[] = "oai";
// GLOBAL: IMPERIALISM 0x0069ad30
char s_mcflavor_0069ad30[] = "ui";
// GLOBAL: IMPERIALISM 0x0069ad34
char s_mcflavor_0069ad34[] = "y";
// GLOBAL: IMPERIALISM 0x0069ad38
char s_mcflavor_0069ad38[] = "ph";
// GLOBAL: IMPERIALISM 0x0069ad3c
char s_mcflavor_0069ad3c[] = "t";
// GLOBAL: IMPERIALISM 0x0069ad40
char s_mcflavor_0069ad40[] = "c";
// GLOBAL: IMPERIALISM 0x0069ad44
char s_mcflavor_0069ad44[] = "C";
// GLOBAL: IMPERIALISM 0x0069ad48
char s_mcflavor_0069ad48[] = "Q";
// GLOBAL: IMPERIALISM 0x0069ad4c
char s_mcflavor_0069ad4c[] = "Ph";
// GLOBAL: IMPERIALISM 0x0069ad50
char s_mcflavor_0069ad50[] = "Ng";
// GLOBAL: IMPERIALISM 0x0069ad54
char s_mcflavor_0069ad54[] = "Nh";
// GLOBAL: IMPERIALISM 0x0069ad58
char s_mcflavor_0069ad58[] = "Ku/Rl";
// GLOBAL: IMPERIALISM 0x0069ad60
char s_mcflavor_0069ad60[] = "Vj/Gvl";
// GLOBAL: IMPERIALISM 0x0069ad68
char s_mcflavor_0069ad68[] = "Ku/Gw";
// GLOBAL: IMPERIALISM 0x0069ad70
char s_mcflavor_0069ad70[] = "Ku/Gvl";
// GLOBAL: IMPERIALISM 0x0069ad78
char s_mcflavor_0069ad78[] = "Kvj/Gvl";
// GLOBAL: IMPERIALISM 0x0069ad84
char s_mcflavor_0069ad84[] = "Kvj/Gw";
// GLOBAL: IMPERIALISM 0x0069ad8c
char s_mcflavor_0069ad8c[] = "ya";
// GLOBAL: IMPERIALISM 0x0069ad90
char s_mcflavor_0069ad90[] = "iye";
// GLOBAL: IMPERIALISM 0x0069ad94
char s_mcflavor_0069ad94[] = "\366y";
// GLOBAL: IMPERIALISM 0x0069ad98
char s_mcflavor_0069ad98[] = "ay";
// GLOBAL: IMPERIALISM 0x0069ad9c
char s_mcflavor_0069ad9c[] = "ey";
// GLOBAL: IMPERIALISM 0x0069ada0
char s_mcflavor_0069ada0[] = "ms";
// GLOBAL: IMPERIALISM 0x0069ada4
char s_mcflavor_0069ada4[] = "kf";
// GLOBAL: IMPERIALISM 0x0069ada8
char s_mcflavor_0069ada8[] = "nt";
// GLOBAL: IMPERIALISM 0x0069adac
char s_mcflavor_0069adac[] = "rd";
// GLOBAL: IMPERIALISM 0x0069adb0
char s_mcflavor_0069adb0[] = "gl";
// GLOBAL: IMPERIALISM 0x0069adb4
char s_mcflavor_0069adb4[] = "dr";
// GLOBAL: IMPERIALISM 0x0069adb8
char s_mcflavor_0069adb8[] = "kh";
// GLOBAL: IMPERIALISM 0x0069adbc
char s_mcflavor_0069adbc[] = "kk";
// GLOBAL: IMPERIALISM 0x0069adc0
char s_mcflavor_0069adc0[] = "pr";
// GLOBAL: IMPERIALISM 0x0069adc4
char s_mcflavor_0069adc4[] = "z";
// GLOBAL: IMPERIALISM 0x0069adc8
char s_mcflavor_0069adc8[] = "lg";
// GLOBAL: IMPERIALISM 0x0069adcc
char s_mcflavor_0069adcc[] = "lv";
// GLOBAL: IMPERIALISM 0x0069add0
char s_mcflavor_0069add0[] = "ks";
// GLOBAL: IMPERIALISM 0x0069add4
char s_mcflavor_0069add4[] = "h";
// GLOBAL: IMPERIALISM 0x0069add8
char s_mcflavor_0069add8[] = "v";
// GLOBAL: IMPERIALISM 0x0069addc
char s_mcflavor_0069addc[] = "ld";
// GLOBAL: IMPERIALISM 0x0069ade0
char s_mcflavor_0069ade0[] = "sr";
// GLOBAL: IMPERIALISM 0x0069ade4
char s_mcflavor_0069ade4[] = "rz";
// GLOBAL: IMPERIALISM 0x0069ade8
char s_mcflavor_0069ade8[] = "nk";
// GLOBAL: IMPERIALISM 0x0069adec
char s_mcflavor_0069adec[] = "zg";
// GLOBAL: IMPERIALISM 0x0069adf0
char s_mcflavor_0069adf0[] = "zn";
// GLOBAL: IMPERIALISM 0x0069adf4
char s_mcflavor_0069adf4[] = "rs";
// GLOBAL: IMPERIALISM 0x0069adf8
char s_mcflavor_0069adf8[] = "zm";
// GLOBAL: IMPERIALISM 0x0069adfc
char s_mcflavor_0069adfc[] = "sk";
// GLOBAL: IMPERIALISM 0x0069ae00
char s_mcflavor_0069ae00[] = "\326";
// GLOBAL: IMPERIALISM 0x0069ae04
char s_mcflavor_0069ae04[] = "Ay";
// GLOBAL: IMPERIALISM 0x0069ae08
char s_mcflavor_0069ae08[] = "U";
// GLOBAL: IMPERIALISM 0x0069ae0c
char s_mcflavor_0069ae0c[] = "Ya";
// GLOBAL: IMPERIALISM 0x0069ae10
char s_mcflavor_0069ae10[] = "Yo";
// GLOBAL: IMPERIALISM 0x0069ae14
char s_mcflavor_0069ae14[] = "Vkw";
// GLOBAL: IMPERIALISM 0x0069ae18
char s_mcflavor_0069ae18[] = "Kvkvkvkvl";
// GLOBAL: IMPERIALISM 0x0069ae24
char s_mcflavor_0069ae24[] = "Vkvkvkw";
// GLOBAL: IMPERIALISM 0x0069ae30
char s_mcflavor_0069ae30[] = "aya";
// GLOBAL: IMPERIALISM 0x0069ae34
char s_mcflavor_0069ae34[] = "yy";
// GLOBAL: IMPERIALISM 0x0069ae38
char s_mcflavor_0069ae38[] = "rsk";
// GLOBAL: IMPERIALISM 0x0069ae3c
char s_mcflavor_0069ae3c[] = "tsk";
// GLOBAL: IMPERIALISM 0x0069ae40
char s_mcflavor_0069ae40[] = "vsk";
// GLOBAL: IMPERIALISM 0x0069ae44
char s_mcflavor_0069ae44[] = "rdl";
// GLOBAL: IMPERIALISM 0x0069ae48
char s_mcflavor_0069ae48[] = "tch";
// GLOBAL: IMPERIALISM 0x0069ae4c
char s_mcflavor_0069ae4c[] = "sn";
// GLOBAL: IMPERIALISM 0x0069ae50
char s_mcflavor_0069ae50[] = "vk";
// GLOBAL: IMPERIALISM 0x0069ae54
char s_mcflavor_0069ae54[] = "stk";
// GLOBAL: IMPERIALISM 0x0069ae58
char s_mcflavor_0069ae58[] = "tn";
// GLOBAL: IMPERIALISM 0x0069ae5c
char s_mcflavor_0069ae5c[] = "lkh";
// GLOBAL: IMPERIALISM 0x0069ae60
char s_mcflavor_0069ae60[] = "tr";
// GLOBAL: IMPERIALISM 0x0069ae64
char s_mcflavor_0069ae64[] = "Ye";
// GLOBAL: IMPERIALISM 0x0069ae68
char s_mcflavor_0069ae68[] = "Sv";
// GLOBAL: IMPERIALISM 0x0069ae6c
char s_mcflavor_0069ae6c[] = "Gl";
// GLOBAL: IMPERIALISM 0x0069ae70
char s_mcflavor_0069ae70[] = "Zl";
// GLOBAL: IMPERIALISM 0x0069ae74
char s_mcflavor_0069ae74[] = "Sh";
// GLOBAL: IMPERIALISM 0x0069ae78
char s_mcflavor_0069ae78[] = "Kl";
// GLOBAL: IMPERIALISM 0x0069ae7c
char s_mcflavor_0069ae7c[] = "oea";
// GLOBAL: IMPERIALISM 0x0069ae80
char s_mcflavor_0069ae80[] = "eo";
// GLOBAL: IMPERIALISM 0x0069ae84
char s_mcflavor_0069ae84[] = "ou";
// GLOBAL: IMPERIALISM 0x0069ae88
char s_mcflavor_0069ae88[] = "eaau";
// GLOBAL: IMPERIALISM 0x0069ae90
char s_mcflavor_0069ae90[] = "aii";
// GLOBAL: IMPERIALISM 0x0069ae94
char s_mcflavor_0069ae94[] = "aui";
// GLOBAL: IMPERIALISM 0x0069ae98
char s_mcflavor_0069ae98[] = "auai";
// GLOBAL: IMPERIALISM 0x0069aea0
char s_mcflavor_0069aea0[] = "auea";
// GLOBAL: IMPERIALISM 0x0069aea8
char s_mcflavor_0069aea8[] = "aau";
// GLOBAL: IMPERIALISM 0x0069aeac
char s_mcflavor_0069aeac[] = "aaui";
// GLOBAL: IMPERIALISM 0x0069aeb4
char s_mcflavor_0069aeb4[] = "aa";
// GLOBAL: IMPERIALISM 0x0069aeb8
char s_mcflavor_0069aeb8[] = "ee";
// GLOBAL: IMPERIALISM 0x0069aebc
char s_mcflavor_0069aebc[] = "oau";
// GLOBAL: IMPERIALISM 0x0069aec0
char s_mcflavor_0069aec0[] = "oe";
// GLOBAL: IMPERIALISM 0x0069aec4
char s_mcflavor_0069aec4[] = "ue";
// GLOBAL: IMPERIALISM 0x0069aec8
char s_mcflavor_0069aec8[] = "oo";
// GLOBAL: IMPERIALISM 0x0069aecc
char s_mcflavor_0069aecc[] = "ae";
// GLOBAL: IMPERIALISM 0x0069aed0
char s_mcflavor_0069aed0[] = "ea";
// GLOBAL: IMPERIALISM 0x0069aed4
char s_mcflavor_0069aed4[] = "aia";
// GLOBAL: IMPERIALISM 0x0069aed8
char s_mcflavor_0069aed8[] = "Oo";
// GLOBAL: IMPERIALISM 0x0069aedc
char s_mcflavor_0069aedc[] = "Oa";
// GLOBAL: IMPERIALISM 0x0069aee0
char s_mcflavor_0069aee0[] = "Cu";
// GLOBAL: IMPERIALISM 0x0069aee4
char s_mcflavor_0069aee4[] = "Cvcvcu";
// GLOBAL: IMPERIALISM 0x0069aeec
char s_mcflavor_0069aeec[] = "Cvcvcvcu";
// GLOBAL: IMPERIALISM 0x0069aef8
char s_mcflavor_0069aef8[] = "Cvcu";
// GLOBAL: IMPERIALISM 0x0069af00
char s_mcflavor_0069af00[] = "Vcvcu";
// GLOBAL: IMPERIALISM 0x0069af08
char s_mcflavor_0069af08[] = "Vcu";
// GLOBAL: IMPERIALISM 0x0069af0c
char s_mcflavor_0069af0c[] = "Vcvcvcu";
// GLOBAL: IMPERIALISM 0x0069af18
char s_mcflavor_0069af18[] = "u'";
// GLOBAL: IMPERIALISM 0x0069af1c
char s_mcflavor_0069af1c[] = "a'i";
// GLOBAL: IMPERIALISM 0x0069af20
char s_mcflavor_0069af20[] = "'a";
// GLOBAL: IMPERIALISM 0x0069af24
char s_mcflavor_0069af24[] = "a'";
// GLOBAL: IMPERIALISM 0x0069af28
char s_mcflavor_0069af28[] = "a'a";
// GLOBAL: IMPERIALISM 0x0069af2c
char s_mcflavor_0069af2c[] = "yd";
// GLOBAL: IMPERIALISM 0x0069af30
char s_mcflavor_0069af30[] = "wf";
// GLOBAL: IMPERIALISM 0x0069af34
char s_mcflavor_0069af34[] = "lt";
// GLOBAL: IMPERIALISM 0x0069af38
char s_mcflavor_0069af38[] = "j";
// GLOBAL: IMPERIALISM 0x0069af3c
char s_mcflavor_0069af3c[] = "bb";
// GLOBAL: IMPERIALISM 0x0069af40
char s_mcflavor_0069af40[] = "dd";
// GLOBAL: IMPERIALISM 0x0069af44
char s_mcflavor_0069af44[] = "dm";
// GLOBAL: IMPERIALISM 0x0069af48
char s_mcflavor_0069af48[] = "sf";
// GLOBAL: IMPERIALISM 0x0069af4c
char s_mcflavor_0069af4c[] = "yr";
// GLOBAL: IMPERIALISM 0x0069af50
char s_mcflavor_0069af50[] = "dh";
// GLOBAL: IMPERIALISM 0x0069af54
char s_mcflavor_0069af54[] = "nf";
// GLOBAL: IMPERIALISM 0x0069af58
char s_mcflavor_0069af58[] = "bh";
// GLOBAL: IMPERIALISM 0x0069af5c
char s_mcflavor_0069af5c[] = "lw";
// GLOBAL: IMPERIALISM 0x0069af60
char s_mcflavor_0069af60[] = "rr";
// GLOBAL: IMPERIALISM 0x0069af64
char s_mcflavor_0069af64[] = "fh";
// GLOBAL: IMPERIALISM 0x0069af68
char s_mcflavor_0069af68[] = "yn";
// GLOBAL: IMPERIALISM 0x0069af6c
char s_mcflavor_0069af6c[] = "zr";
// GLOBAL: IMPERIALISM 0x0069af70
char s_mcflavor_0069af70[] = "mm";
// GLOBAL: IMPERIALISM 0x0069af74
char s_mcflavor_0069af74[] = "q";
// GLOBAL: IMPERIALISM 0x0069af78
char s_mcflavor_0069af78[] = "shd";
// GLOBAL: IMPERIALISM 0x0069af7c
char s_mcflavor_0069af7c[] = "rq";
// GLOBAL: IMPERIALISM 0x0069af80
char s_mcflavor_0069af80[] = "fr";
// GLOBAL: IMPERIALISM 0x0069af84
char s_mcflavor_0069af84[] = "mth";
// GLOBAL: IMPERIALISM 0x0069af88
char s_mcflavor_0069af88[] = "sh";
// GLOBAL: IMPERIALISM 0x0069af8c
char s_mcflavor_0069af8c[] = "'U";
// GLOBAL: IMPERIALISM 0x0069af90
char s_mcflavor_0069af90[] = "'A";
// GLOBAL: IMPERIALISM 0x0069af94
char s_mcflavor_0069af94[] = "Dh";
// GLOBAL: IMPERIALISM 0x0069af98
char s_mcflavor_0069af98[] = "J";
// GLOBAL: IMPERIALISM 0x0069af9c
char s_mcflavor_0069af9c[] = "Y";
// GLOBAL: IMPERIALISM 0x0069afa0
char s_mcflavor_0069afa0[] = "Vj/Gvkvkvkvl";
// GLOBAL: IMPERIALISM 0x0069afb0
char s_mcflavor_0069afb0[] = "Kvkvj/Gvkvl";
// GLOBAL: IMPERIALISM 0x0069afc0
char s_mcflavor_0069afc0[] = "Vku/Gvkvkvl";
// GLOBAL: IMPERIALISM 0x0069afd0
char s_mcflavor_0069afd0[] = "Vj/Rkvkvl";
// GLOBAL: IMPERIALISM 0x0069afdc
char s_mcflavor_0069afdc[] = "Vj/Gvkvkvl";
// GLOBAL: IMPERIALISM 0x0069afec
char s_mcflavor_0069afec[] = "Vj/Rkw";
// GLOBAL: IMPERIALISM 0x0069aff4
char s_mcflavor_0069aff4[] = "Vkvj/Gvkvl";
// GLOBAL: IMPERIALISM 0x0069b004
char s_mcflavor_0069b004[] = "Vj/Gvkvl";
// GLOBAL: IMPERIALISM 0x0069b010
char s_mcflavor_0069b010[] = "Vj/Gvkw";
// GLOBAL: IMPERIALISM 0x0069b01c
char s_mcflavor_0069b01c[] = "iou";
// GLOBAL: IMPERIALISM 0x0069b020
char s_mcflavor_0069b020[] = "ao";
// GLOBAL: IMPERIALISM 0x0069b024
char s_mcflavor_0069b024[] = "uo";
// GLOBAL: IMPERIALISM 0x0069b028
char s_mcflavor_0069b028[] = "iao";
// GLOBAL: IMPERIALISM 0x0069b02c
char s_mcflavor_0069b02c[] = "ngp";
// GLOBAL: IMPERIALISM 0x0069b030
char s_mcflavor_0069b030[] = "ngj";
// GLOBAL: IMPERIALISM 0x0069b034
char s_mcflavor_0069b034[] = "nc";
// GLOBAL: IMPERIALISM 0x0069b038
char s_mcflavor_0069b038[] = "ngt";
// GLOBAL: IMPERIALISM 0x0069b03c
char s_mcflavor_0069b03c[] = "nm";
// GLOBAL: IMPERIALISM 0x0069b040
char s_mcflavor_0069b040[] = "nw";
// GLOBAL: IMPERIALISM 0x0069b044
char s_mcflavor_0069b044[] = "nsh";
// GLOBAL: IMPERIALISM 0x0069b048
char s_mcflavor_0069b048[] = "ngd";
// GLOBAL: IMPERIALISM 0x0069b04c
char s_mcflavor_0069b04c[] = "ngg";
// GLOBAL: IMPERIALISM 0x0069b050
char s_mcflavor_0069b050[] = "ngw";
// GLOBAL: IMPERIALISM 0x0069b054
char s_mcflavor_0069b054[] = "nj";
// GLOBAL: IMPERIALISM 0x0069b058
char s_mcflavor_0069b058[] = "ngh";
// GLOBAL: IMPERIALISM 0x0069b05c
char s_mcflavor_0069b05c[] = "ngb";
// GLOBAL: IMPERIALISM 0x0069b060
char s_mcflavor_0069b060[] = "ns";
// GLOBAL: IMPERIALISM 0x0069b064
char s_mcflavor_0069b064[] = "nq";
// GLOBAL: IMPERIALISM 0x0069b068
char s_mcflavor_0069b068[] = "ngy";
// GLOBAL: IMPERIALISM 0x0069b06c
char s_mcflavor_0069b06c[] = "zh";
// GLOBAL: IMPERIALISM 0x0069b070
char s_mcflavor_0069b070[] = "nqzh";
// GLOBAL: IMPERIALISM 0x0069b078
char s_mcflavor_0069b078[] = "ngl";
// GLOBAL: IMPERIALISM 0x0069b07c
char s_mcflavor_0069b07c[] = "ngsh";
// GLOBAL: IMPERIALISM 0x0069b084
char s_mcflavor_0069b084[] = "ngx";
// GLOBAL: IMPERIALISM 0x0069b088
char s_mcflavor_0069b088[] = "ny";
// GLOBAL: IMPERIALISM 0x0069b08c
char s_mcflavor_0069b08c[] = "ngm";
// GLOBAL: IMPERIALISM 0x0069b090
char s_mcflavor_0069b090[] = "ngzh";
// GLOBAL: IMPERIALISM 0x0069b098
char s_mcflavor_0069b098[] = "nzh";
// GLOBAL: IMPERIALISM 0x0069b09c
char s_mcflavor_0069b09c[] = "nx";
// GLOBAL: IMPERIALISM 0x0069b0a0
char s_mcflavor_0069b0a0[] = "Ch";
// GLOBAL: IMPERIALISM 0x0069b0a4
char s_mcflavor_0069b0a4[] = "Zh";
// GLOBAL: IMPERIALISM 0x0069b0a8
char s_mcflavor_0069b0a8[] = "yo";
// GLOBAL: IMPERIALISM 0x0069b0ac
char s_mcflavor_0069b0ac[] = "oya";
// GLOBAL: IMPERIALISM 0x0069b0b0
char s_mcflavor_0069b0b0[] = "ii";
// GLOBAL: IMPERIALISM 0x0069b0b4
char s_mcflavor_0069b0b4[] = "iya";
// GLOBAL: IMPERIALISM 0x0069b0b8
char s_mcflavor_0069b0b8[] = "Oi";
// GLOBAL: IMPERIALISM 0x0069b0bc
char s_mcflavor_0069b0bc[] = "O";
// GLOBAL: IMPERIALISM 0x0069b0c0
char s_mcflavor_0069b0c0[] = "Ai";
// GLOBAL: IMPERIALISM 0x0069b0c4
char s_mcflavor_0069b0c4[] = "Ao";
// GLOBAL: IMPERIALISM 0x0069b0c8
char s_mcflavor_0069b0c8[] = "Kw";
// GLOBAL: IMPERIALISM 0x0069b0cc
char s_mcflavor_0069b0cc[] = "kch";
// GLOBAL: IMPERIALISM 0x0069b0d0
char s_mcflavor_0069b0d0[] = "lch";
// GLOBAL: IMPERIALISM 0x0069b0d4
char s_mcflavor_0069b0d4[] = "ngs";
// GLOBAL: IMPERIALISM 0x0069b0d8
char s_mcflavor_0069b0d8[] = "mch";
// GLOBAL: IMPERIALISM 0x0069b0dc
char s_mcflavor_0069b0dc[] = "ls";
// GLOBAL: IMPERIALISM 0x0069b0e0
char s_mcflavor_0069b0e0[] = "kp";
// GLOBAL: IMPERIALISM 0x0069b0e4
char s_mcflavor_0069b0e4[] = "Hw";
// GLOBAL: IMPERIALISM 0x0069b0e8
char s_mcflavor_0069b0e8[] = "uu";
// GLOBAL: IMPERIALISM 0x0069b0ec
char s_mcflavor_0069b0ec[] = "i'";
// GLOBAL: IMPERIALISM 0x0069b0f0
char s_mcflavor_0069b0f0[] = "iu";
// GLOBAL: IMPERIALISM 0x0069b0f4
char s_mcflavor_0069b0f4[] = "tsy";
// GLOBAL: IMPERIALISM 0x0069b0f8
char s_mcflavor_0069b0f8[] = "ntsy";
// GLOBAL: IMPERIALISM 0x0069b100
char s_mcflavor_0069b100[] = "nty";
// GLOBAL: IMPERIALISM 0x0069b104
char s_mcflavor_0069b104[] = "ksh";
// GLOBAL: IMPERIALISM 0x0069b108
char s_mcflavor_0069b108[] = "ts";
// GLOBAL: IMPERIALISM 0x0069b10c
char s_mcflavor_0069b10c[] = "kt";
// GLOBAL: IMPERIALISM 0x0069b110
char s_mcflavor_0069b110[] = "dj";
// GLOBAL: IMPERIALISM 0x0069b114
char s_mcflavor_0069b114[] = "ngn";
// GLOBAL: IMPERIALISM 0x0069b118
char s_mcflavor_0069b118[] = "jj";
// GLOBAL: IMPERIALISM 0x0069b11c
char s_mcflavor_0069b11c[] = "kn";
// GLOBAL: IMPERIALISM 0x0069b120
char s_mcflavor_0069b120[] = "kj";
// GLOBAL: IMPERIALISM 0x0069b124
char s_mcflavor_0069b124[] = "dl";
// GLOBAL: IMPERIALISM 0x0069b128
char s_mcflavor_0069b128[] = "rm";
// GLOBAL: IMPERIALISM 0x0069b12c
char s_mcflavor_0069b12c[] = "lm";
// GLOBAL: IMPERIALISM 0x0069b130
char s_mcflavor_0069b130[] = "rn";
// GLOBAL: IMPERIALISM 0x0069b134
char s_mcflavor_0069b134[] = "dn";
// GLOBAL: IMPERIALISM 0x0069b138
char s_mcflavor_0069b138[] = "Ui";
// GLOBAL: IMPERIALISM 0x0069b13c
char s_mcflavor_0069b13c[] = "Kvkvkvl/Kvkvl";
// GLOBAL: IMPERIALISM 0x0069b14c
char s_mcflavor_0069b14c[] = "Vkvkvkvkw";
// GLOBAL: IMPERIALISM 0x0069b158
char s_mcflavor_0069b158[] = "kw";
// GLOBAL: IMPERIALISM 0x0069b15c
char s_mcflavor_0069b15c[] = "shw";
// GLOBAL: IMPERIALISM 0x0069b160
char s_mcflavor_0069b160[] = "cks";
// GLOBAL: IMPERIALISM 0x0069b164
char s_mcflavor_0069b164[] = "hns";
// GLOBAL: IMPERIALISM 0x0069b168
char s_mcflavor_0069b168[] = "ry";
// GLOBAL: IMPERIALISM 0x0069b16c
char s_mcflavor_0069b16c[] = "rth";
// GLOBAL: IMPERIALISM 0x0069b170
char s_mcflavor_0069b170[] = "ghg";
// GLOBAL: IMPERIALISM 0x0069b174
char s_mcflavor_0069b174[] = "mbl";
// GLOBAL: IMPERIALISM 0x0069b178
char s_mcflavor_0069b178[] = "rns";
// GLOBAL: IMPERIALISM 0x0069b17c
char s_mcflavor_0069b17c[] = "ghtsbr";
// GLOBAL: IMPERIALISM 0x0069b184
char s_mcflavor_0069b184[] = "rls";
// GLOBAL: IMPERIALISM 0x0069b188
char s_mcflavor_0069b188[] = "dg";
// GLOBAL: IMPERIALISM 0x0069b18c
char s_mcflavor_0069b18c[] = "stm";
// GLOBAL: IMPERIALISM 0x0069b190
char s_mcflavor_0069b190[] = "psg";
// GLOBAL: IMPERIALISM 0x0069b194
char s_mcflavor_0069b194[] = "rsm";
// GLOBAL: IMPERIALISM 0x0069b198
char s_mcflavor_0069b198[] = "md";
// GLOBAL: IMPERIALISM 0x0069b19c
char s_mcflavor_0069b19c[] = "tst";
// GLOBAL: IMPERIALISM 0x0069b1a0
char s_mcflavor_0069b1a0[] = "nchm";
// GLOBAL: IMPERIALISM 0x0069b1a8
char s_mcflavor_0069b1a8[] = "pn";
// GLOBAL: IMPERIALISM 0x0069b1ac
char s_mcflavor_0069b1ac[] = "thn";
// GLOBAL: IMPERIALISM 0x0069b1b0
char s_mcflavor_0069b1b0[] = "ngf";
// GLOBAL: IMPERIALISM 0x0069b1b4
char s_mcflavor_0069b1b4[] = "pt";
// GLOBAL: IMPERIALISM 0x0069b1b8
char s_mcflavor_0069b1b8[] = "ckn";
// GLOBAL: IMPERIALISM 0x0069b1bc
char s_mcflavor_0069b1bc[] = "rbl";
// GLOBAL: IMPERIALISM 0x0069b1c0
char s_mcflavor_0069b1c0[] = "ryl";
// GLOBAL: IMPERIALISM 0x0069b1c4
char s_mcflavor_0069b1c4[] = "ngsg";
// GLOBAL: IMPERIALISM 0x0069b1cc
char s_mcflavor_0069b1cc[] = "ckw";
// GLOBAL: IMPERIALISM 0x0069b1d0
char s_mcflavor_0069b1d0[] = "mt";
// GLOBAL: IMPERIALISM 0x0069b1d4
char s_mcflavor_0069b1d4[] = "pl";
// GLOBAL: IMPERIALISM 0x0069b1d8
char s_mcflavor_0069b1d8[] = "rtl";
// GLOBAL: IMPERIALISM 0x0069b1dc
char s_mcflavor_0069b1dc[] = "mst";
// GLOBAL: IMPERIALISM 0x0069b1e0
char s_mcflavor_0069b1e0[] = "df";
// GLOBAL: IMPERIALISM 0x0069b1e4
char s_mcflavor_0069b1e4[] = "lf";
// GLOBAL: IMPERIALISM 0x0069b1e8
char s_mcflavor_0069b1e8[] = "nds";
// GLOBAL: IMPERIALISM 0x0069b1ec
char s_mcflavor_0069b1ec[] = "yw";
// GLOBAL: IMPERIALISM 0x0069b1f0
char s_mcflavor_0069b1f0[] = "mpt";
// GLOBAL: IMPERIALISM 0x0069b1f4
char s_mcflavor_0069b1f4[] = "rlt";
// GLOBAL: IMPERIALISM 0x0069b1f8
char s_mcflavor_0069b1f8[] = "ptf";
// GLOBAL: IMPERIALISM 0x0069b1fc
char s_mcflavor_0069b1fc[] = "ngsb";
// GLOBAL: IMPERIALISM 0x0069b204
char s_mcflavor_0069b204[] = "wcr";
// GLOBAL: IMPERIALISM 0x0069b208
char s_mcflavor_0069b208[] = "thf";
// GLOBAL: IMPERIALISM 0x0069b20c
char s_mcflavor_0069b20c[] = "rh";
// GLOBAL: IMPERIALISM 0x0069b210
char s_mcflavor_0069b210[] = "yf";
// GLOBAL: IMPERIALISM 0x0069b214
char s_mcflavor_0069b214[] = "sm";
// GLOBAL: IMPERIALISM 0x0069b218
char s_mcflavor_0069b218[] = "sd";
// GLOBAL: IMPERIALISM 0x0069b21c
char s_mcflavor_0069b21c[] = "sw";
// GLOBAL: IMPERIALISM 0x0069b220
char s_mcflavor_0069b220[] = "thg";
// GLOBAL: IMPERIALISM 0x0069b224
char s_mcflavor_0069b224[] = "ldg";
// GLOBAL: IMPERIALISM 0x0069b228
char s_mcflavor_0069b228[] = "yt";
// GLOBAL: IMPERIALISM 0x0069b22c
char s_mcflavor_0069b22c[] = "mpst";
// GLOBAL: IMPERIALISM 0x0069b234
char s_mcflavor_0069b234[] = "tf";
// GLOBAL: IMPERIALISM 0x0069b238
char s_mcflavor_0069b238[] = "lth";
// GLOBAL: IMPERIALISM 0x0069b23c
char s_mcflavor_0069b23c[] = "ckh";
// GLOBAL: IMPERIALISM 0x0069b240
char s_mcflavor_0069b240[] = "ckl";
// GLOBAL: IMPERIALISM 0x0069b244
char s_mcflavor_0069b244[] = "xt";
// GLOBAL: IMPERIALISM 0x0069b248
char s_mcflavor_0069b248[] = "lh";
// GLOBAL: IMPERIALISM 0x0069b24c
char s_mcflavor_0069b24c[] = "ndsw";
// GLOBAL: IMPERIALISM 0x0069b254
char s_mcflavor_0069b254[] = "nchl";
// GLOBAL: IMPERIALISM 0x0069b25c
char s_mcflavor_0069b25c[] = "nst";
// GLOBAL: IMPERIALISM 0x0069b260
char s_mcflavor_0069b260[] = "ct";
// GLOBAL: IMPERIALISM 0x0069b264
char s_mcflavor_0069b264[] = "rw";
// GLOBAL: IMPERIALISM 0x0069b268
char s_mcflavor_0069b268[] = "Eu";
// GLOBAL: IMPERIALISM 0x0069b26c
char s_mcflavor_0069b26c[] = "Ea";
// GLOBAL: IMPERIALISM 0x0069b270
char s_mcflavor_0069b270[] = "Bl";
// GLOBAL: IMPERIALISM 0x0069b274
char s_mcflavor_0069b274[] = "Pl";
// GLOBAL: IMPERIALISM 0x0069b278
char s_mcflavor_0069b278[] = "Sm";
// GLOBAL: IMPERIALISM 0x0069b27c
char s_mcflavor_0069b27c[] = "Cr";
// GLOBAL: IMPERIALISM 0x0069b280
char s_mcflavor_0069b280[] = "Wh";
// GLOBAL: IMPERIALISM 0x0069b284
char s_mcflavor_0069b284[] = "Str";
// GLOBAL: IMPERIALISM 0x0069b288
char s_mcflavor_0069b288[] = "Cl";
// GLOBAL: IMPERIALISM 0x0069b28c
char s_mcflavor_0069b28c[] = "Br";
// GLOBAL: IMPERIALISM 0x0069b290
char s_mcflavor_0069b290[] = "Gr";
// GLOBAL: IMPERIALISM 0x0069b294
char s_mcflavor_0069b294[] = "oie";
// GLOBAL: IMPERIALISM 0x0069b298
char s_mcflavor_0069b298[] = "ys";
// GLOBAL: IMPERIALISM 0x0069b29c
char s_mcflavor_0069b29c[] = "rc";
// GLOBAL: IMPERIALISM 0x0069b2a0
char s_mcflavor_0069b2a0[] = "ntr";
// GLOBAL: IMPERIALISM 0x0069b2a4
char s_mcflavor_0069b2a4[] = "sg";
// GLOBAL: IMPERIALISM 0x0069b2a8
char s_mcflavor_0069b2a8[] = "cl";
// GLOBAL: IMPERIALISM 0x0069b2ac
char s_mcflavor_0069b2ac[] = "tl";
// GLOBAL: IMPERIALISM 0x0069b2b0
char s_mcflavor_0069b2b0[] = "gn";
// GLOBAL: IMPERIALISM 0x0069b2b4
char s_mcflavor_0069b2b4[] = "lp";
// GLOBAL: IMPERIALISM 0x0069b2b8
char s_mcflavor_0069b2b8[] = "gr";
// GLOBAL: IMPERIALISM 0x0069b2bc
char s_mcflavor_0069b2bc[] = "Rh";
// GLOBAL: IMPERIALISM 0x0069b2c0
char s_mcflavor_0069b2c0[] = "Pr";
// GLOBAL: IMPERIALISM 0x0069b2c4
char s_mcflavor_0069b2c4[] = "-";
// GLOBAL: IMPERIALISM 0x0069b2c8
char s_mcflavor_0069b2c8[] = "mbr";
// GLOBAL: IMPERIALISM 0x0069b2cc
char s_mcflavor_0069b2cc[] = "cc";
// GLOBAL: IMPERIALISM 0x0069b2d0
char s_mcflavor_0069b2d0[] = "gg";
// GLOBAL: IMPERIALISM 0x0069b2d4
char s_mcflavor_0069b2d4[] = "zz";
// GLOBAL: IMPERIALISM 0x0069b2d8
char s_mcflavor_0069b2d8[] = "mp";
// GLOBAL: IMPERIALISM 0x0069b2dc
char s_mcflavor_0069b2dc[] = "br";
// GLOBAL: IMPERIALISM 0x0069b2e0
char s_mcflavor_0069b2e0[] = "sc";
// GLOBAL: IMPERIALISM 0x0069b2e4
char s_mcflavor_0069b2e4[] = "mky";
// GLOBAL: IMPERIALISM 0x0069b2e8
char s_mcflavor_0069b2e8[] = "rsky";
// GLOBAL: IMPERIALISM 0x0069b2f0
char s_mcflavor_0069b2f0[] = "ssky";
// GLOBAL: IMPERIALISM 0x0069b2f8
char s_mcflavor_0069b2f8[] = "by";
// GLOBAL: IMPERIALISM 0x0069b2fc
char s_mcflavor_0069b2fc[] = "nsky";
// GLOBAL: IMPERIALISM 0x0069b304
char s_mcflavor_0069b304[] = "vy";
// GLOBAL: IMPERIALISM 0x0069b308
char s_mcflavor_0069b308[] = "ty";
// GLOBAL: IMPERIALISM 0x0069b30c
char s_mcflavor_0069b30c[] = "zny";
// GLOBAL: IMPERIALISM 0x0069b310
char s_mcflavor_0069b310[] = "hy";
// GLOBAL: IMPERIALISM 0x0069b314
char s_mcflavor_0069b314[] = "cky";
// GLOBAL: IMPERIALISM 0x0069b318
char s_mcflavor_0069b318[] = "chy";
// GLOBAL: IMPERIALISM 0x0069b31c
char s_mcflavor_0069b31c[] = "nky";
// GLOBAL: IMPERIALISM 0x0069b320
char s_mcflavor_0069b320[] = "dy";
// GLOBAL: IMPERIALISM 0x0069b324
char s_mcflavor_0069b324[] = "rny";
// GLOBAL: IMPERIALISM 0x0069b328
char s_mcflavor_0069b328[] = "ly";
// GLOBAL: IMPERIALISM 0x0069b32c
char s_mcflavor_0069b32c[] = "vsky";
// GLOBAL: IMPERIALISM 0x0069b334
char s_mcflavor_0069b334[] = "lky";
// GLOBAL: IMPERIALISM 0x0069b338
char s_mcflavor_0069b338[] = "lny";
// GLOBAL: IMPERIALISM 0x0069b33c
char s_mcflavor_0069b33c[] = "ky";
// GLOBAL: IMPERIALISM 0x0069b340
char s_mcflavor_0069b340[] = "hl";
// GLOBAL: IMPERIALISM 0x0069b344
char s_mcflavor_0069b344[] = "cht";
// GLOBAL: IMPERIALISM 0x0069b348
char s_mcflavor_0069b348[] = "mc";
// GLOBAL: IMPERIALISM 0x0069b34c
char s_mcflavor_0069b34c[] = "mpl";
// GLOBAL: IMPERIALISM 0x0069b350
char s_mcflavor_0069b350[] = "pc";
// GLOBAL: IMPERIALISM 0x0069b354
char s_mcflavor_0069b354[] = "kr";
// GLOBAL: IMPERIALISM 0x0069b358
char s_mcflavor_0069b358[] = "zsk";
// GLOBAL: IMPERIALISM 0x0069b35c
char s_mcflavor_0069b35c[] = "mr";
// GLOBAL: IMPERIALISM 0x0069b360
char s_mcflavor_0069b360[] = "dc";
// GLOBAL: IMPERIALISM 0x0069b364
char s_mcflavor_0069b364[] = "dk";
// GLOBAL: IMPERIALISM 0x0069b368
char s_mcflavor_0069b368[] = "tk";
// GLOBAL: IMPERIALISM 0x0069b36c
char s_mcflavor_0069b36c[] = "bn";
// GLOBAL: IMPERIALISM 0x0069b370
char s_mcflavor_0069b370[] = "rv";
// GLOBAL: IMPERIALISM 0x0069b374
char s_mcflavor_0069b374[] = "dhr";
// GLOBAL: IMPERIALISM 0x0069b378
char s_mcflavor_0069b378[] = "hr";
// GLOBAL: IMPERIALISM 0x0069b37c
char s_mcflavor_0069b37c[] = "dv";
// GLOBAL: IMPERIALISM 0x0069b380
char s_mcflavor_0069b380[] = "cn";
// GLOBAL: IMPERIALISM 0x0069b384
char s_mcflavor_0069b384[] = "ssk";
// GLOBAL: IMPERIALISM 0x0069b388
char s_mcflavor_0069b388[] = "jn";
// GLOBAL: IMPERIALISM 0x0069b38c
char s_mcflavor_0069b38c[] = "dz";
// GLOBAL: IMPERIALISM 0x0069b390
char s_mcflavor_0069b390[] = "lc";
// GLOBAL: IMPERIALISM 0x0069b394
char s_mcflavor_0069b394[] = "vn";
// GLOBAL: IMPERIALISM 0x0069b398
char s_mcflavor_0069b398[] = "lk";
// GLOBAL: IMPERIALISM 0x0069b39c
char s_mcflavor_0069b39c[] = "nsk";
// GLOBAL: IMPERIALISM 0x0069b3a0
char s_mcflavor_0069b3a0[] = "vc";
// GLOBAL: IMPERIALISM 0x0069b3a4
char s_mcflavor_0069b3a4[] = "Chr";
// GLOBAL: IMPERIALISM 0x0069b3a8
char s_mcflavor_0069b3a8[] = "Zd";
// GLOBAL: IMPERIALISM 0x0069b3ac
char s_mcflavor_0069b3ac[] = "Mn";
// GLOBAL: IMPERIALISM 0x0069b3b0
char s_mcflavor_0069b3b0[] = "Skl";
// GLOBAL: IMPERIALISM 0x0069b3b4
char s_mcflavor_0069b3b4[] = "Vys";
// GLOBAL: IMPERIALISM 0x0069b3b8
char s_mcflavor_0069b3b8[] = "Krt";
// GLOBAL: IMPERIALISM 0x0069b3bc
char s_mcflavor_0069b3bc[] = "Hrnc";
// GLOBAL: IMPERIALISM 0x0069b3c4
char s_mcflavor_0069b3c4[] = "Kv";
// GLOBAL: IMPERIALISM 0x0069b3c8
char s_mcflavor_0069b3c8[] = "Kys";
// GLOBAL: IMPERIALISM 0x0069b3cc
char s_mcflavor_0069b3cc[] = "Zb";
// GLOBAL: IMPERIALISM 0x0069b3d0
char s_mcflavor_0069b3d0[] = "Hl";
// GLOBAL: IMPERIALISM 0x0069b3d4
char s_mcflavor_0069b3d4[] = "Trst";
// GLOBAL: IMPERIALISM 0x0069b3dc
char s_mcflavor_0069b3dc[] = "Vrb";
// GLOBAL: IMPERIALISM 0x0069b3e0
char s_mcflavor_0069b3e0[] = "Sk";
// GLOBAL: IMPERIALISM 0x0069b3e4
char s_mcflavor_0069b3e4[] = "Dv";
// GLOBAL: IMPERIALISM 0x0069b3e8
char s_mcflavor_0069b3e8[] = "Hn";
// GLOBAL: IMPERIALISM 0x0069b3ec
char s_mcflavor_0069b3ec[] = "Zv";
// GLOBAL: IMPERIALISM 0x0069b3f0
char s_mcflavor_0069b3f0[] = "Vr";
// GLOBAL: IMPERIALISM 0x0069b3f4
char s_mcflavor_0069b3f4[] = "Dr";
// GLOBAL: IMPERIALISM 0x0069b3f8
char s_mcflavor_0069b3f8[] = "Bystr";
// GLOBAL: IMPERIALISM 0x0069b400
char s_mcflavor_0069b400[] = "Trn";
// GLOBAL: IMPERIALISM 0x0069b404
char s_mcflavor_0069b404[] = "Sl";
// GLOBAL: IMPERIALISM 0x0069b408
char s_mcflavor_0069b408[] = "Hr";
// GLOBAL: IMPERIALISM 0x0069b40c
char s_mcflavor_0069b40c[] = "eau";
// GLOBAL: IMPERIALISM 0x0069b410
char s_mcflavor_0069b410[] = "pply";
// GLOBAL: IMPERIALISM 0x0069b418
char s_mcflavor_0069b418[] = "ght";
// GLOBAL: IMPERIALISM 0x0069b41c
char s_mcflavor_0069b41c[] = "lls";
// GLOBAL: IMPERIALISM 0x0069b420
char s_mcflavor_0069b420[] = "ws";
// GLOBAL: IMPERIALISM 0x0069b424
char s_mcflavor_0069b424[] = "rgh";
// GLOBAL: IMPERIALISM 0x0069b428
char s_mcflavor_0069b428[] = "sky";
// GLOBAL: IMPERIALISM 0x0069b42c
char s_mcflavor_0069b42c[] = "tty";
// GLOBAL: IMPERIALISM 0x0069b430
char s_mcflavor_0069b430[] = "rry";
// GLOBAL: IMPERIALISM 0x0069b434
char s_mcflavor_0069b434[] = "rts";
// GLOBAL: IMPERIALISM 0x0069b438
char s_mcflavor_0069b438[] = "wk";
// GLOBAL: IMPERIALISM 0x0069b43c
char s_mcflavor_0069b43c[] = "ft";
// GLOBAL: IMPERIALISM 0x0069b440
char s_mcflavor_0069b440[] = "wn";
// GLOBAL: IMPERIALISM 0x0069b444
char s_mcflavor_0069b444[] = "nry";
// GLOBAL: IMPERIALISM 0x0069b448
char s_mcflavor_0069b448[] = "hn";
// GLOBAL: IMPERIALISM 0x0069b44c
char s_mcflavor_0069b44c[] = "mphr";
// GLOBAL: IMPERIALISM 0x0069b454
char s_mcflavor_0069b454[] = "rdf";
// GLOBAL: IMPERIALISM 0x0069b458
char s_mcflavor_0069b458[] = "rct";
// GLOBAL: IMPERIALISM 0x0069b45c
char s_mcflavor_0069b45c[] = "ntp";
// GLOBAL: IMPERIALISM 0x0069b460
char s_mcflavor_0069b460[] = "wh";
// GLOBAL: IMPERIALISM 0x0069b464
char s_mcflavor_0069b464[] = "db";
// GLOBAL: IMPERIALISM 0x0069b468
char s_mcflavor_0069b468[] = "shl";
// GLOBAL: IMPERIALISM 0x0069b46c
char s_mcflavor_0069b46c[] = "lyb";
// GLOBAL: IMPERIALISM 0x0069b470
char s_mcflavor_0069b470[] = "yb";
// GLOBAL: IMPERIALISM 0x0069b474
char s_mcflavor_0069b474[] = "nbr";
// GLOBAL: IMPERIALISM 0x0069b478
char s_mcflavor_0069b478[] = "rtf";
// GLOBAL: IMPERIALISM 0x0069b47c
char s_mcflavor_0069b47c[] = "wkb";
// GLOBAL: IMPERIALISM 0x0069b480
char s_mcflavor_0069b480[] = "ssw";
// GLOBAL: IMPERIALISM 0x0069b484
char s_mcflavor_0069b484[] = "shm";
// GLOBAL: IMPERIALISM 0x0069b488
char s_mcflavor_0069b488[] = "ffm";
// GLOBAL: IMPERIALISM 0x0069b48c
char s_mcflavor_0069b48c[] = "nkl";
// GLOBAL: IMPERIALISM 0x0069b490
char s_mcflavor_0069b490[] = "ssfr";
// GLOBAL: IMPERIALISM 0x0069b498
char s_mcflavor_0069b498[] = "llf";
// GLOBAL: IMPERIALISM 0x0069b49c
char s_mcflavor_0069b49c[] = "gd";
// GLOBAL: IMPERIALISM 0x0069b4a0
char s_mcflavor_0069b4a0[] = "wst";
// GLOBAL: IMPERIALISM 0x0069b4a4
char s_mcflavor_0069b4a4[] = "tw";
// GLOBAL: IMPERIALISM 0x0069b4a8
char s_mcflavor_0069b4a8[] = "nsw";
// GLOBAL: IMPERIALISM 0x0069b4ac
char s_mcflavor_0069b4ac[] = "rj";
// GLOBAL: IMPERIALISM 0x0069b4b0
char s_mcflavor_0069b4b0[] = "gh";
// GLOBAL: IMPERIALISM 0x0069b4b4
char s_mcflavor_0069b4b4[] = "mpb";
// GLOBAL: IMPERIALISM 0x0069b4b8
char s_mcflavor_0069b4b8[] = "sbr";
// GLOBAL: IMPERIALISM 0x0069b4bc
char s_mcflavor_0069b4bc[] = "lymp";
// GLOBAL: IMPERIALISM 0x0069b4c4
char s_mcflavor_0069b4c4[] = "rsv";
// GLOBAL: IMPERIALISM 0x0069b4c8
char s_mcflavor_0069b4c8[] = "rp";
// GLOBAL: IMPERIALISM 0x0069b4cc
char s_mcflavor_0069b4cc[] = "mf";
// GLOBAL: IMPERIALISM 0x0069b4d0
char s_mcflavor_0069b4d0[] = "ngr";
// GLOBAL: IMPERIALISM 0x0069b4d4
char s_mcflavor_0069b4d4[] = "ftw";
// GLOBAL: IMPERIALISM 0x0069b4d8
char s_mcflavor_0069b4d8[] = "mph";
// GLOBAL: IMPERIALISM 0x0069b4dc
char s_mcflavor_0069b4dc[] = "xtr";
// GLOBAL: IMPERIALISM 0x0069b4e0
char s_mcflavor_0069b4e0[] = "cs";
// GLOBAL: IMPERIALISM 0x0069b4e4
char s_mcflavor_0069b4e4[] = "cr";
// GLOBAL: IMPERIALISM 0x0069b4e8
char s_mcflavor_0069b4e8[] = "lr";
// GLOBAL: IMPERIALISM 0x0069b4ec
char s_mcflavor_0069b4ec[] = "rpr";
// GLOBAL: IMPERIALISM 0x0069b4f0
char s_mcflavor_0069b4f0[] = "xc";
// GLOBAL: IMPERIALISM 0x0069b4f4
char s_mcflavor_0069b4f4[] = "ncr";
// GLOBAL: IMPERIALISM 0x0069b4f8
char s_mcflavor_0069b4f8[] = "ttl";
// GLOBAL: IMPERIALISM 0x0069b4fc
char s_mcflavor_0069b4fc[] = "spr";
// GLOBAL: IMPERIALISM 0x0069b500
char s_mcflavor_0069b500[] = "wp";
// GLOBAL: IMPERIALISM 0x0069b504
char s_mcflavor_0069b504[] = "lph";
// GLOBAL: IMPERIALISM 0x0069b508
char s_mcflavor_0069b508[] = "rwh";
// GLOBAL: IMPERIALISM 0x0069b50c
char s_mcflavor_0069b50c[] = "nr";
// GLOBAL: IMPERIALISM 0x0069b510
char s_mcflavor_0069b510[] = "ff";
// GLOBAL: IMPERIALISM 0x0069b514
char s_mcflavor_0069b514[] = "nv";
// GLOBAL: IMPERIALISM 0x0069b518
char s_mcflavor_0069b518[] = "yl";
// GLOBAL: IMPERIALISM 0x0069b51c
char s_mcflavor_0069b51c[] = "Lyk";
// GLOBAL: IMPERIALISM 0x0069b520
char s_mcflavor_0069b520[] = "Spr";
// GLOBAL: IMPERIALISM 0x0069b524
char s_mcflavor_0069b524[] = "Sc";
// GLOBAL: IMPERIALISM 0x0069b528
char s_mcflavor_0069b528[] = "Fl";
// GLOBAL: IMPERIALISM 0x0069b52c
char s_mcflavor_0069b52c[] = "Santa ";
// GLOBAL: IMPERIALISM 0x0069b534
char s_mcflavor_0069b534[] = "San ";
// GLOBAL: IMPERIALISM 0x0069b53c
char s_mcflavor_0069b53c[] = "Feces";
// GLOBAL: IMPERIALISM 0x0069b544
char s_mcflavor_0069b544[] = "Bitch";
// GLOBAL: IMPERIALISM 0x0069b54c
char s_mcflavor_0069b54c[] = "Fart";
// GLOBAL: IMPERIALISM 0x0069b554
char s_mcflavor_0069b554[] = "Jism";
// GLOBAL: IMPERIALISM 0x0069b55c
char s_mcflavor_0069b55c[] = "Turd";
// GLOBAL: IMPERIALISM 0x0069b564
char s_mcflavor_0069b564[] = "Smegma";
// GLOBAL: IMPERIALISM 0x0069b56c
char s_mcflavor_0069b56c[] = "Schweinhund";
// GLOBAL: IMPERIALISM 0x0069b57c
char s_mcflavor_0069b57c[] = "Mierda";
// GLOBAL: IMPERIALISM 0x0069b584
char s_mcflavor_0069b584[] = "Maricon";
// GLOBAL: IMPERIALISM 0x0069b590
char s_mcflavor_0069b590[] = "Cabron";
// GLOBAL: IMPERIALISM 0x0069b598
char s_mcflavor_0069b598[] = "Tit";
// GLOBAL: IMPERIALISM 0x0069b59c
char s_mcflavor_0069b59c[] = "Coger";
// GLOBAL: IMPERIALISM 0x0069b5a4
char s_mcflavor_0069b5a4[] = "Chinga";
// GLOBAL: IMPERIALISM 0x0069b5ac
char s_mcflavor_0069b5ac[] = "Scheiss";
// GLOBAL: IMPERIALISM 0x0069b5b8
char s_mcflavor_0069b5b8[] = "Merde";
// GLOBAL: IMPERIALISM 0x0069b5c0
char s_mcflavor_0069b5c0[] = "Fag";
// GLOBAL: IMPERIALISM 0x0069b5c4
char s_mcflavor_0069b5c4[] = "Cock";
// GLOBAL: IMPERIALISM 0x0069b5cc
char s_mcflavor_0069b5cc[] = "Hitler";
// GLOBAL: IMPERIALISM 0x0069b5d4
char s_mcflavor_0069b5d4[] = "Nazi";
// GLOBAL: IMPERIALISM 0x0069b5dc
char s_mcflavor_0069b5dc[] = "Spic";
// GLOBAL: IMPERIALISM 0x0069b5e4
char s_mcflavor_0069b5e4[] = "Kike";
// GLOBAL: IMPERIALISM 0x0069b5ec
char s_mcflavor_0069b5ec[] = "Gook";
// GLOBAL: IMPERIALISM 0x0069b5f4
char s_mcflavor_0069b5f4[] = "Nigger";
// GLOBAL: IMPERIALISM 0x0069b5fc
char s_mcflavor_0069b5fc[] = "Twat";
// GLOBAL: IMPERIALISM 0x0069b604
char s_mcflavor_0069b604[] = "Pussy";
// GLOBAL: IMPERIALISM 0x0069b60c
char s_mcflavor_0069b60c[] = "Piss";
// GLOBAL: IMPERIALISM 0x0069b614
char s_mcflavor_0069b614[] = "Vagina";
// GLOBAL: IMPERIALISM 0x0069b61c
char s_mcflavor_0069b61c[] = "Penis";
// GLOBAL: IMPERIALISM 0x0069b624
char s_mcflavor_0069b624[] = "Ass";
// GLOBAL: IMPERIALISM 0x0069b628
char s_mcflavor_0069b628[] = "Whore";
// GLOBAL: IMPERIALISM 0x0069b630
char s_mcflavor_0069b630[] = "Cunt";
// GLOBAL: IMPERIALISM 0x0069b638
char s_mcflavor_0069b638[] = "Shit";
// GLOBAL: IMPERIALISM 0x0069b640
char s_mcflavor_0069b640[] = "Fuck";
// GLOBAL: IMPERIALISM 0x0069b7fc
char s_Data_scores_dat[] = "Data/scores.dat";

// GLOBAL: IMPERIALISM 0x00658640
extern const float g_HexHighlightScreenScale = -0.3125f;

// GLOBAL: IMPERIALISM 0x006a4084
short g_creditsPlaybackActive = 0;

// GLOBAL: IMPERIALISM 0x0066db58
extern const short g_tradeBookCategoryByTabAndTechState[2][17] = {
    {13, 14, 15, 16, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4, 5, -1, -1},
    {13, 14, 15, 16, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3, 4, 5, 6}};
// GLOBAL: IMPERIALISM 0x006a2fe0
CPoint g_diplomacyPopupVisiblePosition(8, 7);
// GLOBAL: IMPERIALISM 0x006a3020
CPoint g_diplomacyPopupOffscreenPosition(2000, 2000);

// GLOBAL: IMPERIALISM 0x006a2410
int g_InfoBarDummyOrigin[2] = {0};

// GLOBAL: IMPERIALISM 0x0064c5d8
short g_MapOrderResourceRollWeightTable[6][6] = {
    {50, 20, 30, 40, 30, 30}, {50, 20, 30, 50, 30, 20}, {40, 35, 25, 55, 30, 15},
    {30, 50, 20, 65, 20, 15}, {20, 65, 15, 70, 20, 10}, {10, 80, 10, 80, 10, 10},
};

// GLOBAL: IMPERIALISM 0x00696400
short g_cityProductionReserveByPolicyBand[4] = {0, 2, 6, 12};

// GLOBAL: IMPERIALISM 0x00696408
short g_aInteriorMinisterNeedPriorityOrder[10] = {17, 18, 20, 19, 2, 3, 4, 0, 1, 5};

// GLOBAL: IMPERIALISM 0x00696450
float g_cityProductionUpgradeRatioThreshold[4] = {2.0f, 2.0f, 2.0f, 0.0f};

// Groups city-action capability slots into their upgrade-compatible families.
// GLOBAL: IMPERIALISM 0x00650670
short g_cityActionCapabilityGroupBySlot[32] = {0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2,
                                               0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// GLOBAL: IMPERIALISM 0x0064fab0
short g_cityBuildingSoundCueOffsets[16] = {2, 3, 4, 5, 0, 1, 6, 10, 11, 12, 13, 7, 8, 9, 14, 35};

// One-time and recurring diplomacy-grant amounts selected by the four grant rows.
// GLOBAL: IMPERIALISM 0x00696948
short g_awDiplomacyGrantValueTable[4] = {1000, 3000, 5000, 10000};

// GLOBAL: IMPERIALISM 0x00696950
short g_awDiplomacyTradePolicyIconValueTable[7] = {95, 90, 75, 50, 25, 0, 300};

// GLOBAL: IMPERIALISM 0x00669f10
double g_dNavyDamageSplitRatioA = 0.25;
// GLOBAL: IMPERIALISM 0x00669f18
double g_dNavyDamageSplitRatioB = 0.75;

// GLOBAL: IMPERIALISM 0x00669ef8
double g_dNavyHitChanceRangeScale = 0.5;
// GLOBAL: IMPERIALISM 0x00669f00
float g_fNavyHitChanceCubeOffset = -1.0f;
// GLOBAL: IMPERIALISM 0x00669f04
float g_fNavyHitChanceNumerator = 80.0f;

// GLOBAL: IMPERIALISM 0x0065c168
extern "C" const int kLoungeStatusGlyphIds[5] = {0x11fe, 0x11ff, 0x1200, 0x1201, 0x1202};

// GLOBAL: IMPERIALISM 0x0065c648
extern "C" const short g_anTerrainFlowTypeByRiverSpriteCode[16] = {0, 1, 2, 2, 3, 3, 4, 4,
                                                                   4, 4, 5, 5, 6, 6, 7, 8};

// GLOBAL: IMPERIALISM 0x0065c668
extern "C" const short g_anTerrainFlowDirections[9][2] = {{0, 2}, {0, 3}, {0, 4}, {1, 3}, {1, 4},
                                                          {1, 5}, {2, 4}, {2, 5}, {3, 5}};
