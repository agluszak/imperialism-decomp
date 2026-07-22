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
class TInfoBarText;

#include "game/TArmyPlayer.h"
#include "game/TAmbitApplication.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"
#include "game/sea_geometry.h"
#include "game/app_init_globals.h"
#include "game/UiRuntimeContext.h"
#include "game/TNetMgr.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/TNewsMgr.h"
#include "game/TNavyMgr.h"
#include "game/TSimMgr.h"
#include "game/TAssetMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TLanguageMgr.h"
#include "game/THelpMgr.h"
#include "game/TControl.h"
#include "game/TInfoBarText.h"
#include "game/TAnimator.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TBackdropWindow.h"
#include "game/TSetupRandomMapPicture.h"

// Typed C++ linkage — see typed-recovered-globals.mdc (not inside extern "C").
// GLOBAL: IMPERIALISM 0x006a4310
TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount] = {0};
// GLOBAL: IMPERIALISM 0x006a2158
TDisplayMgr* g_pDisplayMgr = 0;
// Bounds of the TAnimator offscreen surface (only known live reader:
// TAnimator::InitializeUiTransientObjectRegistry at 0x4a0b20).
// GLOBAL: IMPERIALISM 0x006a2228
int g_nUiAnimatorSurfaceBoundsWidth = 0;
// GLOBAL: IMPERIALISM 0x006a222c
int g_nUiAnimatorSurfaceBoundsHeight = 0;
// Monotonic registry-tag counter for TIdleMeAnimation instances, seeded with the
// byte pattern "0TUA" (multichar 'AUT0'); the class-name string "TIdleMeAnimation"
// follows at 0x695938, which Ghidra folds into one s_0TUATIdleMeAnimation label.
// GLOBAL: IMPERIALISM 0x00695934
int g_nIdleMeAnimationNextRegistryTag = 0x41555430;
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
TGreatPower* g_apNationStates_End;
// GLOBAL: IMPERIALISM 0x006a20f8
TSimMgr* g_pSimMgr = 0;
// GLOBAL: IMPERIALISM 0x006a21b8
THelpMgr* g_pHelpMgr = 0;
// GLOBAL: IMPERIALISM 0x006a43e8
TNewsMgr* g_pInterNationEventQueueManager = 0;
// GLOBAL: IMPERIALISM 0x006a1344
TAmbitApplication* g_pGlobalUiRootController = 0;
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
char* g_pBattleReportSharedText_0064dc30 = g_szEmptyString;
// Shared text pointer the mini-civ row view (0x4ab970) seeds its control text and
// assembled-string accumulator from; only the empty-string default is observed so far.
// GLOBAL: IMPERIALISM 0x0064cb18
char* g_pMiniCivSharedText_0064cb18 = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0065c830
char* g_pShipFractionSharedText_0065c830 = g_szEmptyString;
// Shared empty-text pointer used by the diplomacy panel Setup methods. Unlike the
// empty string storage itself, the original reads this pointer through an absolute load.
// GLOBAL: IMPERIALISM 0x00654ec8
char* g_pDiplomacyPanelEmptyText_00654ec8 = g_szEmptyString;
// Local player's display name, read by TLoungeDialog::DoPostCreate when posting the
// lobby-chat "connected" announcement (LobbyChatEvent9Packet's sender/message text).
// GLOBAL: IMPERIALISM 0x0065c160
char* g_pLoungeLocalPlayerNameSharedText_0065c160 = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x00668b88
char* g_pStatusPictureMainSharedText_00668b88 = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x00695448
extern const unsigned char g_MapContextStaticTable_00695448[0x20] = {
    1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0};
char g_vtblTSortedByRelationshipList = 0;
// Last cursor edge-auto-scroll timestamp in GetTickCountDiv16 units
// (TAmbitApplication::HandleCursor, 0x49e320).
// GLOBAL: IMPERIALISM 0x006a21c0
int g_lastEdgeAutoScrollTick16 = 0;
// GLOBAL: IMPERIALISM 0x00695278
int g_nSaveFormatVersion = -1;
// File header emitted by TAmbitFileBasedDocument::DoWrite and validated by DoRead.
// GLOBAL: IMPERIALISM 0x0064c094
extern const int g_nAmbitSaveFileMagic = 0x414d4249;
// GLOBAL: IMPERIALISM 0x0064c098
extern const int g_nCurrentAmbitSaveFormatVersion = 0x3e;
// GLOBAL: IMPERIALISM 0x0069527c
extern const char g_szUAmbitSourcePath[] = "D:\\Ambit\\Cross\\UAmbit.cpp";
// Per-great-power quarter phase used to stagger the diplomacy planning pass.
// GLOBAL: IMPERIALISM 0x00697818
extern const short g_aDiplomacyPlanningQuarterPhaseByNation[7] = {0, 3, 1, 2, 1, 2, 0};
// FourCC tags and their parallel TSimMgr member-handler table used by
// ProcessScenarioScript. Single-inheritance MSVC5 member pointers are plain code
// pointers, matching the original 27-entry dispatch table.
// GLOBAL: IMPERIALISM 0x00662978
extern const unsigned int g_anScenarioScriptInstructionTags[27] = {
    0x6c61626f, 0x63617061, 0x77617265, 0x61726d79, 0x63697669, 0x73686970, 0x7472616e,
    0x64657665, 0x7261696c, 0x706f7274, 0x74656368, 0x70726963, 0x656d6261, 0x73756273,
    0x74726561, 0x79656172, 0x70726f76, 0x7a6f6e65, 0x636e616d, 0x72656c61, 0x706e616d,
    0x63617368, 0x666c6167, 0x74796572, 0x74626172, 0x74636c72, 0x636f756e,
};
// GLOBAL: IMPERIALISM 0x00698b50
void (TSimMgr::* g_apfnScenarioScriptInstructionHandlers[27])(void*) = {
    &TSimMgr::HandleTurnInstruction_Labo_SetNationLaborTierCounts,
    &TSimMgr::HandleTurnInstruction_Capa_ApplyNationSlotValueWithDelta,
    &TSimMgr::HandleTurnInstruction_Ware_ApplyNationIndexedShortAndRefresh,
    &TSimMgr::HandleTurnInstruction_Army_DeserializeAndCreateRecruitOrders,
    &TSimMgr::HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder,
    &TSimMgr::HandleTurnInstruction_Ship_DeserializeAndCreatePrimaryOrders,
    &TSimMgr::HandleTurnInstruction_Tran_SetNationTransportStat,
    &TSimMgr::HandleTurnInstruction_Deve_ApplyMapDevelopmentEntry,
    &TSimMgr::HandleTurnInstruction_Rail_ApplyRailPlacementAndCashBonus,
    &TSimMgr::HandleTurnInstruction_Port_ApplyPortPlacementAndCashBonus,
    &TSimMgr::HandleTurnInstruction_Tech_ApplyTechUnlockAndNotifyNations,
    &TSimMgr::HandleTurnInstruction_Pric_ApplyDiplomacyPriceEntry,
    &TSimMgr::HandleTurnInstruction_Emba_SetEmbassyRelationFlags,
    &TSimMgr::HandleTurnInstruction_Subs_ApplyNationSubsidyEntry,
    &TSimMgr::HandleTurnInstruction_Trea_ApplyTreatyAndRelationEntry,
    &TSimMgr::HandleTurnInstruction_Year_UpdateScenarioYearFieldScaledBy4,
    &TSimMgr::HandleTurnInstruction_Prov_ApplyProvinceAssignmentEntry,
    &TSimMgr::HandleTurnInstruction_Zone_AssignMapActionContextNameByNodeId,
    &TSimMgr::HandleTurnInstruction_Cnam_AssignCountryName,
    &TSimMgr::HandleTurnInstruction_Rela_SetNationRelationValue,
    &TSimMgr::HandleTurnInstruction_Pnam_AssignProvinceName,
    &TSimMgr::HandleTurnInstruction_Cash_SetNationCash,
    &TSimMgr::HandleTurnInstruction_Flag_SetNationFlagAndRefresh,
    &TSimMgr::HandleTurnInstruction_Tyer_SetCityOrderCapabilityTierValue,
    &TSimMgr::HandleTurnInstruction_Tbar_SetNationRelationBarValue,
    &TSimMgr::HandleTurnInstruction_Tclr_ResetNationRelationBars,
    &TSimMgr::HandleTurnInstruction_Coun_SetCountrySlotState,
};
// GLOBAL: IMPERIALISM 0x006a4398
unsigned char g_bScenarioScriptTerminationRequested = 0;
// GLOBAL: IMPERIALISM 0x006a43b8
int g_nScenarioScriptInstructionCount = 0;
// GLOBAL: IMPERIALISM 0x006a3ee0
int g_UnknownMapOrderExecutionGuard_006a3ee0 = 0;
// GLOBAL: IMPERIALISM 0x006a30b4
int g_colorFillAssertGuard_006a30b4 = 0;
// Upper-cased command-line switch literal matched by
// ImperialismCommandLineInfo::ParseParam (0x4133d0). Linker-pooled with the same "L"
// literal used as a flavor-text syllable in map_context_flavor_builders.cpp -- named
// after the literal value, not either consumer, since neither owns the address.
// GLOBAL: IMPERIALISM 0x00694250
char g_szLiteralL_00694250[] = "L";
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
// GLOBAL: IMPERIALISM 0x006a1358
void* g_pAmbitDeveloperAssertProbe_006A1358 = 0;

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
// GLOBAL: IMPERIALISM 0x00695168
char g_szQuickDrawSourcePath_00695168[] = "D:\\Ambit\\QuickDraw.cpp";
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
// Provisional: selects the CDib picture-preview blit path in TDDTemplateDialog::OnPaint
// (0x0047d5f0) — nonzero (1 in the binary) picks the CreateCompatibleDC + BitBlt of a
// device bitmap; zero picks a plain StretchDIBits from the stored DIB bits. Only observed
// use so far is that OnPaint; name is a behavioral guess.
// GLOBAL: IMPERIALISM 0x00694c50
int g_useCompatibleBitmapBlit = 1;
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

// Default text baked into the event 0x3ba planet-name dialog.
// GLOBAL: IMPERIALISM 0x00694528
char g_szUiDefaultPlanetName_00694528[] = "Skyron";
// GLOBAL: IMPERIALISM 0x00694530
char g_szUiPickAPlanet_00694530[] = "Pick a planet";
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
// GLOBAL: IMPERIALISM 0x00696728
char g_szUCountrySourcePath_00696728[] = "D:\\Ambit\\Cross\\UCountry.cpp";
// InitializeDiplomacyMinisterActionControlsAndLabels' (0x4f4620) 6 action-button tags,
// in construction order: info/trty/gran/trad/coun/offr.
// GLOBAL: IMPERIALISM 0x00696960
int g_diplomacyActionButtonTagTable_00696960[6] = {0x696e666f, 0x74727479, 0x6772616e,
                                                   0x74726164, 0x636f756e, 0x6f666672};
// TCouncilView::DoEvent's council-control 4-char tag table ("tfni", "ttrt", "targ",
// "tart", "tuoc", "rffo" as stored); also the same function's hover-text tag variants.
// GLOBAL: IMPERIALISM 0x00696978
unsigned int g_councilControlTagTable[6] = {0x696e6674, 0x74727474, 0x67726174,
                                            0x74726174, 0x636f7574, 0x6f666672};
// TInfoPanelView::Draw label-column coordinates, in the panel's parent coordinate space.
// GLOBAL: IMPERIALISM 0x006969b0
short g_infoPanelLabelXByRow_006969b0[4] = {0x48, 0x48, 0x48, 0x48};
// GLOBAL: IMPERIALISM 0x006969c0
short g_infoPanelLabelYByRow_006969c0[4] = {0x198, 0x1a9, 0x1ba, 0x1cb};
// GLOBAL: IMPERIALISM 0x006a143c
int g_McAppUiFlag_006A143C = 0;
// GLOBAL: IMPERIALISM 0x00698ab8
char g_szSetupScreensSourcePath_00698AB8[] = "D:\\Ambit\\Cross\\USetupScreens.cpp";
// GLOBAL: IMPERIALISM 0x006a4264
int g_SetupScreensAssertFlag_006A4264 = 0;
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
int g_nQuickDrawPenHorizontalSize = 0;
// GLOBAL: IMPERIALISM 0x006a1d0c
int g_nQuickDrawPenVerticalSize = 0;
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
TextStyle g_QuickDrawCachedFontPreset = {0, 0, 0, 0};
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
TextStyle g_QuickDrawMeasureFontPreset = {0, 0, 0, 0};
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
// GLOBAL: IMPERIALISM 0x006a5458
int g_nUiFrameClipOriginX = 0;
// GLOBAL: IMPERIALISM 0x006a545c
int g_nUiFrameClipOriginY = 0;
// GLOBAL: IMPERIALISM 0x006a1ca0
TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
// Statically initialized to the sentinel address (the dword at 0x006950f8 holds
// 0x006a1ca0 in the original), not null — the restore path in
// BuildStrategicMapCommodityIconAtlasFrom700To722 captures this before the first
// SetGWorld and would otherwise restore a null context.
// GLOBAL: IMPERIALISM 0x006950f8
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead = &g_defaultQuickDrawSurfaceSentinel;
// Zero in the raw .data image; the CRT static-init ctor 0x494040
// (TQuickDrawClipStateInitializer in quickdraw_rendering.cpp) seeds it with
// &g_defaultQuickDrawSurfaceSentinel before WinMain.
// GLOBAL: IMPERIALISM 0x006a1d60
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext = 0;
// GLOBAL: IMPERIALISM 0x006a30a8
TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext = 0;
// Cached snapshot of g_pPrimaryRenderSurfaceContext, stamped by
// TCitySiteView::DoPostCreate after allocating its own surface.
// GLOBAL: IMPERIALISM 0x006a3450
TQuickDrawSurfaceContext* g_pCitySiteCachedPrimaryRenderSurfaceContext = 0;
// Scratch DIB used only while TColorKeyPicture composites its tagged background and
// transparent foreground before presenting the result.
// GLOBAL: IMPERIALISM 0x006a4194
CDib* g_pColorKeyCompositeDib = 0;

// GLOBAL: IMPERIALISM 0x00697320
short g_aStrategicMapNeighborHighlightTiles_00697320[6] = {-1, -1, -1, -1, -1, -1};

// GLOBAL: IMPERIALISM 0x006a3370
CPoint g_MapInteractionPreviewPoint_006a3370(0, 0);
// GLOBAL: IMPERIALISM 0x006a33b4
int g_MapInteractionPreviewRowParity_006a33b4 = 0;
// GLOBAL: IMPERIALISM 0x006a33b8
int g_MapInteractionPreviewColumnParity_006a33b8 = 0;
// GLOBAL: IMPERIALISM 0x006a1da0
CDC* g_pQuickDrawMemoryDc = nullptr;
// GLOBAL: IMPERIALISM 0x006a1dbc
HGDIOBJ g_hQuickDrawSavedBitmap = nullptr;
// GLOBAL: IMPERIALISM 0x006a1db0
int g_nActiveQuickDrawSurfaceFlags = 0;
// McAppUI's Windows compatibility cursor hooks assert when their corresponding
// availability gate is zero. Neither gate has another retail-binary xref.
// GLOBAL: IMPERIALISM 0x006a1dc8
int g_QuickDrawSetCursorAssertGate = 0;
// GLOBAL: IMPERIALISM 0x006a1dcc
int g_QuickDrawGetCursorAssertGate = 0;

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

// Trade sell propagation tags.
const int kTradeSellPropagationTags[17] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

// TMinorTradeBidsDialog's typed view of the control-tag run. The first 17 entries are
// the commodity controls; the trailing values are the exact sentinel words adjacent to
// the 23 slots read by the retail loop (the 24th word pins the original data extent).
// GLOBAL: IMPERIALISM 0x0066b1a0
const int g_tradeBidNationMetricControlTags[24] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520, 0x72733620, 0x6d613020,
    0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420, 0x6d613520, 0x67643020, 0x67643120, 0x67643220,
    0x67643320, 0,          -1,         -1,         -1,         0,          1,          -1};

// Treaty-dialog panel and cell tags, stored as packed four-character control IDs.
// GLOBAL: IMPERIALISM 0x0066b100
const unsigned int g_majorTreatyPanelTags[7] = {0x47503020, 0x47503120, 0x47503220, 0x47503320,
                                                0x47503420, 0x47503520, 0x47503620};
// GLOBAL: IMPERIALISM 0x0066b13c
const unsigned int g_minorTreatyPanelTags[16] = {
    0x6d372020, 0x6d382020, 0x6d392020, 0x6d313020, 0x6d313120, 0x6d313220, 0x6d313320, 0x6d313420,
    0x6d313520, 0x6d313620, 0x6d313720, 0x6d313820, 0x6d313920, 0x6d323020, 0x6d323120, 0x6d323220};
// GLOBAL: IMPERIALISM 0x0066b180
const unsigned int g_majorTreatyCellTags[7] = {0x72475030, 0x72475031, 0x72475032, 0x72475033,
                                               0x72475034, 0x72475035, 0x72475036};

// Industry action cost weight tables
// GLOBAL: IMPERIALISM 0x00650758
float g_AiDevelopmentResourceBudgetScale_00650758 = 1000.0f;
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
short g_cachedAiCityActionNationSlot_006967d4 = -1;
// GLOBAL: IMPERIALISM 0x006967d8
short g_cachedAiCityActionTurnTick_006967d8 = -1;
// GLOBAL: IMPERIALISM 0x006a2ea0
float g_cachedAiCityActionContextBias[3] = {0.0f, 0.0f, 0.0f};

// GLOBAL: IMPERIALISM 0x00696198
short g_anCityBuildingSlotCoords[36] = {200, 235, 340, 300, 281, 184, 340, 266, 87, 286, 230, 310,
                                        340, 139, 240, 35,  50,  220, 50,  107, 50, 35,  340, 139,
                                        82,  35,  300, 35,  340, 44,  150, 95,  1,  0,   1,   0};

// GLOBAL: IMPERIALISM 0x006a2998
CRect g_aCityBuildingHoverSelectionRects[16];

// Packed int table consumed by the city-building screen layout (icon/highlight coordinates
// and 0/1 flags; per-field semantics not yet recovered). Populated by
// InitializeCityBuildingLayoutData.
// GLOBAL: IMPERIALISM 0x006a24e8
int g_anCityBuildingLayoutValues[164] = {0};

// 31 action-button rects for the city-building screen, placement-constructed by
// InitializeCityBuildingLayoutData (immediately after g_anCityBuildingLayoutValues).
// GLOBAL: IMPERIALISM 0x006a2778
CRect g_aCityBuildingActionRects[31];

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
// Reader: Function_0049cc60 @ 0x0049cc60 when nonzero.
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
int SetGlobalUiInvalidationFlagAndReturnPrevious(int newValue) {
  int previous = g_McAppUiActiveFlag_006950AC;
  g_McAppUiActiveFlag_006950AC = newValue;
  return previous;
}

// FUNCTION: IMPERIALISM 0x00489a70
int GetMcAppUiActiveFlag() {
  return g_McAppUiActiveFlag_006950AC;
}

// FUNCTION: IMPERIALISM 0x00489a90
int ClearGlobalUiInvalidationFlagAndReturnPrevious() {
  int previous = g_McAppUiActiveFlag_006950AC;
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

// 1.0 constant (double), used by CompareMissionOrderEntriesByPriorityScore (0x536090)
// to compute each side's "remaining priority" as 1.0 - GetWeightedSatisfaction().
// GLOBAL: IMPERIALISM 0x0065a470
extern const double g_MissionScoreOneConstant_0065a470 = 1.0;

// Same conceptual pair as above (0.0f mul/div selector, 1.0 "remaining priority" base),
// read by AssignTrackedEntryActionsByProfileToOrdersOrUnits' (0x4eb8b0) inline scoring.
// Per-personality defense-minister FP weights returned by the slot-0x60
// weight getter (0x4ec0a0 family; flag selects between the pair).
// GLOBAL: IMPERIALISM 0x006548e0
extern const float g_DefenseMinisterWeightZero_006548E0 = 0.0f;
// GLOBAL: IMPERIALISM 0x006548e8
extern const double g_MinisterWeightHalf_006548E8 = 0.5;
// GLOBAL: IMPERIALISM 0x006548f0
extern const double g_MinisterWeightOne_006548F0 = 1.0;
// GLOBAL: IMPERIALISM 0x006548f8
extern const double g_BismarckWeightHigh_006548F8 = 0.9;
// GLOBAL: IMPERIALISM 0x00654900
extern const double g_BismarckWeightLow_00654900 = 0.6;
// GLOBAL: IMPERIALISM 0x00654908
extern const float g_DefenderMinisterWeight_00654908 = 0.75f;
// GLOBAL: IMPERIALISM 0x00654910
extern const double g_BullyWeightLow_00654910 = 0.7;
// GLOBAL: IMPERIALISM 0x00654918
extern const double g_BullyWeightHigh_00654918 = 0.8;

// GLOBAL: IMPERIALISM 0x006545c8
extern const double g_AiPressureUnsetSentinel_006545c8 = -1.0;
// GLOBAL: IMPERIALISM 0x006545d0
extern const float g_MissionDefaultScore_006545d0 = 0.0f;
// Orphaned neighbor constant (no known reader yet) sitting between the two named
// constants above; declared to keep the surrounding data bytes byte-faithful.
// GLOBAL: IMPERIALISM 0x006545d4
extern const float g_UnreferencedConstant_006545d4 = -1.0f;
// GLOBAL: IMPERIALISM 0x006545d8
extern const double g_MissionScoreOneConstant_006545d8 = 1.0;
// GLOBAL: IMPERIALISM 0x006545e0
extern const float g_AiPressureRatioCap_006545e0 = 1.0f;
// GLOBAL: IMPERIALISM 0x006545e8
extern const double g_AiPressureMidpointScale_006545e8 = 0.5;
// 0.0 (double) threshold used by the same function's score-positivity checks.
// GLOBAL: IMPERIALISM 0x006545f0
extern const double g_MissionScoreZeroThreshold_006545f0 = 0.0;
// Competing missions of the same class must beat the next entry's value/cost ratio by
// ten percent before consuming that class from the available mask (0x4eb6b0).
// GLOBAL: IMPERIALISM 0x006545f8
extern const double g_MissionEligibilityRatioMargin_006545f8 = 1.1;

// GLOBAL: IMPERIALISM 0x006543e8
extern const float g_AiPressurePeerScale_006543e8 = 1.1f;

// Weighting factor (0.2) applied to each adjacent region's score when diffusing the
// strategic heatmap (RecomputeTileStrategicScoreHeatmap 0x518130).
// GLOBAL: IMPERIALISM 0x00658780
float g_TileHeatmapNeighborDiffusionFactor = 0.2f;

// Map-interaction preview scale factors (default 1/64 = 0.015625), multiplied into the map
// dialog's rect layout by TMapDialog::Draw (0x51e260). Runtime-set to the default
// by InitializeMapInteractionPreviewScale{X,Y}Default (0x51e0b0 / 0x51e0e0), so zero on disk.
// GLOBAL: IMPERIALISM 0x006a3410
double g_MapPreviewScaleX6A3410;
// GLOBAL: IMPERIALISM 0x006a33d0
double g_MapPreviewScaleY6A33D0;
// GLOBAL: IMPERIALISM 0x006a3360
extern double g_mapCellRowScale_006a3360;
// GLOBAL: IMPERIALISM 0x006a3388
extern double g_mapCellColumnScale_006a3388;

// Two more 1/64 (0.015625) scale-factor doubles reset to default by the same defaults-table
// initializers (0x49c0c0 / 0x49c0f0); g_ScaleDefault6A1FC0 is scaled by
// UpdateGlobalWord6A2008FromScaled6A1FC0 (0x49c120). Zero on disk (runtime-set).
// GLOBAL: IMPERIALISM 0x006a1fe8
double g_ScaleDefault6A1FE8;
// GLOBAL: IMPERIALISM 0x006a1fc0
double g_ScaleDefault6A1FC0;

// Two dword slots in the 0x6a1e20 reset region, zeroed together by the cleanup handler
// ResetGlobalPair6A1E20And6A1E24 (0x49b9d0). Only ever written (to 0); purpose not yet
// recovered. Zero on disk.
// GLOBAL: IMPERIALISM 0x006a1e20
int g_ResetStateDword6A1E20;
// GLOBAL: IMPERIALISM 0x006a1e24
int g_ResetStateDword6A1E24;
// More dword slots in the same 0x6a1exx/0x6a1fxx reset region, each zeroed by its own
// ResetGlobalPair cleanup handler (0x49b9f0 / 0x49bc00 / 0x49bc20). Only ever written to 0.
// GLOBAL: IMPERIALISM 0x006a1e48
int g_ResetStateDword6A1E48;
// GLOBAL: IMPERIALISM 0x006a1e4c
int g_ResetStateDword6A1E4C;
// GLOBAL: IMPERIALISM 0x006a1e70
int g_ResetStateDword6A1E70;
// GLOBAL: IMPERIALISM 0x006a1e74
int g_ResetStateDword6A1E74;
// GLOBAL: IMPERIALISM 0x006a1f38
int g_ResetStateDword6A1F38;
// GLOBAL: IMPERIALISM 0x006a1f3c
int g_ResetStateDword6A1F3C;

// Order-type index rankings (0..13) sorted by descending descriptor weight, rebuilt by
// TNavyMgr::INavyMgr (0x556610): by resolveWeight, calculateWeight, and
// navyPriorityWeight respectively. Runtime-filled, so zero in the on-disk image.
// GLOBAL: IMPERIALISM 0x006a3e28
short g_NavyResolveOrderRanking[14];
// GLOBAL: IMPERIALISM 0x006a3e50
short g_NavyMissionOrderRanking[14];
// GLOBAL: IMPERIALISM 0x006a3e90
short g_NavyPriorityOrderRanking[14];

// Minister-skill-indexed float coefficient tables (DAT_0065xxxx), indexed by a
// minister's skill value at +0x0C. Used by TGreatPower vtable slots 0x88-0x8c.
float g_DAT_Value_00653308[8] = {0.699999988079071f, 1.100000023841858f, 1.2000000476837158f, 1.5f, 1.0f, 0.8999999761581421f, 0.699999988079071f, 0.0f};
float g_DAT_Value_00653328[8] = {1.0f, 1.0f, 1.2999999523162842f, 1.2999999523162842f, 1.2999999523162842f, 0.0f, 0.6000000238418579f, 0.699999988079071f};
float g_DAT_Value_00653340[8] = {0.6000000238418579f, 0.699999988079071f, 0.699999988079071f, 0.699999988079071f, 0.800000011920929f, 0.6000000238418579f, 0.6000000238418579f, 0.0f};
float g_DAT_Value_00653360[8] = {0.699999988079071f, 1.100000023841858f, 1.2999999523162842f, 0.8999999761581421f, 1.0f, 0.0f, 0.5f, 0.6000000238418579f};
float g_DAT_Value_00653378[8] = {0.5f, 0.6000000238418579f, 0.6000000238418579f, 0.6000000238418579f, 0.699999988079071f, 0.5f, 0.5f, 0.0f};
float g_DAT_Value_00653398[8] = {1.0f, 1.0f, 1.2000000476837158f, 0.800000011920929f, 0.8999999761581421f, 0.0f, 0.4000000059604645f, 0.5f};
float g_DAT_006533b0_Value_006533B0[8] = {0.4000000059604645f, 0.5f, 0.5f, 0.5f, 0.6000000238418579f, 0.4000000059604645f, 0.4000000059604645f, 0.0f};
float g_DAT_006533d0_Value_006533D0[8] = {1.100000023841858f, 1.0f, 1.2999999523162842f, 0.699999988079071f, 1.100000023841858f, 0.0f, 0.4000000059604645f, 0.5f};
float g_DAT_006533e8_Value_006533E8[8] = {0.4000000059604645f, 0.5f, 0.5f, 0.5f, 0.6000000238418579f, 0.4000000059604645f, 0.4000000059604645f, 0.0f};
float g_DAT_Value_00653408[8] = {0.8999999761581421f, 0.800000011920929f, 1.100000023841858f, 0.5f, 0.8999999761581421f, 0.0f, 1.5f, 1.5f};

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

// Per-unit-type stat table (7 shorts per type; rows for unit types 0x00-0x1d) and
// per-stat divisor baseline used by TMilitaryUnit::GetUnitTypeStatPercent (0x5c3530).
short g_UnitTypeStatTable_0066EB88[30][7] = {0};
short g_UnitTypeStatDivisorTable_0066ED30[7] = {0};

// Per-order-type sort priority (short table at 0x6966d0), used by the TGreatPower
// slot 0x55 tracked-order selection sort (0x004e0290).
short g_DAT_006966d0_Value_006966D0[16] = {2, 0, 4, 3, 1, 5, 0, 0, 0, 0, 0, 0, 18260, 25970, 29793, 28496};

// Cursor resource id by civilian-tile-order action code (short table at 0x696678, 12
// entries), used by TCivMgr::LookupCivilianTileOrderCursorTokenByActionIndex (0x4d2930).
// GLOBAL: IMPERIALISM 0x00696678
short g_civilianTileOrderCursorTokenTable[12] = {0,    1008, 0,    1004, 1003, 1002,
                                                 1018, 1019, 1001, 1003, 1011, 1025};

// Cursor resource ids selected by TArmyMgr's two map cursor state classifiers.
// GLOBAL: IMPERIALISM 0x00695668
short g_mapCursorTokenByStateIndex_00695668[12] = {0, 0, 1000, 0, 0, 0, 1011, 1011, 1010, 0, 0, 0};
// GLOBAL: IMPERIALISM 0x00695680
short g_civilianMapCursorTokenByStateIndex_00695680[12] = {0,    1008, 1000, 1005, 1006, 1007,
                                                           1011, 1011, 1010, 0,    0,    0};

// Per-unit-type tactical category code (short table at 0x695528, 30 unit types + 2
// pad); category 0 counts as garrison strength in TGreatPower slot 0x11 (0x004d87e0),
// category 8 marks the sapper/engineer types (24-26), 9 the last tier (27-29).
// Tactical view metrics (bss; written by the tactical-view metric setters
// 0x5a6830 / 0x5a6860 / 0x5a6895, read by the live-battle initializer 0x5a9d90).
// GLOBAL: IMPERIALISM 0x006a5430
int g_nTacticalTileWidthPx_006A5430 = 0;
// GLOBAL: IMPERIALISM 0x006a5434
int g_nTacticalTileRowHeightPx_006A5434 = 0;
// GLOBAL: IMPERIALISM 0x006a5448
int g_nTacticalBattlefieldSurfaceWidth_006A5448 = 0;
// GLOBAL: IMPERIALISM 0x006a544c
int g_nTacticalBattlefieldSurfaceHeight_006A544C = 0;
// GLOBAL: IMPERIALISM 0x006a5498
int g_nTacticalUnitSpriteCellWidth_006A5498 = 0;
// GLOBAL: IMPERIALISM 0x006a549c
int g_nTacticalUnitSpriteCellHeight_006A549C = 0;

// Per-unit-type tactical range (int table at 0x6699e8, 30 unit types); artillery on
// the defending side (side20 == 1, combat category 2) gets +1 from the fort walls.
// GLOBAL: IMPERIALISM 0x006699e8
int g_anUnitTypeTacticalRangeByType_006699E8[30] = {5,  5,  5,  5,  3,  3,  9,  11, 8,  8,
                                                    8,  8,  5,  5,  12, 14, 10, 10, 10, 10,
                                                    10, 12, 15, 17, 5,  8,  10, 0,  0,  0};

// GLOBAL: IMPERIALISM 0x00695528
short g_awTacticalUnitCategoryCodeBySlot[32] = {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                                                0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9, 0, 0};

// Per-unit-type combat/composition class (short table at 0x695380, 30 unit types + 2
// pad).
// GLOBAL: IMPERIALISM 0x00695380
short g_awUnitCombatClassBySlot[32] = {1, 2, 1, 1, 3, 2, 2, 1, 1, 2, 1, 1, 3, 2, 2, 1,
                                       1, 2, 1, 1, 3, 3, 2, 1, 1, 2, 3, 2, 2, 2, 0, 0};
// Stack composition class lookup (byte table at 0x6953c0); indexed [minClass + maxClass*4].
// GLOBAL: IMPERIALISM 0x006953c0
unsigned char g_abStackCompositionClassTable[16] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 3, 0, 0, 3, 4, 5};
// Per-unit-type strength-weighting percent (short table at 0x6953e8, 30 unit types + 2
// pad), read by TDefenseMinister::BuildHexAreaTileIndexListIntoAllocatedBuffer as
// weightPercent * TMilitaryUnit::field_34 / 100.
// GLOBAL: IMPERIALISM 0x006953e8
short g_anUnitStrengthWeightPercentBySlot[32] = {
    50,  50,  100, 125, 75,  150, 0, 0, 75, 100, 150, 175, 100, 200, 0, 0,
    100, 150, 225, 250, 225, 600, 0, 0, 0,  0,   0,   0,   0,   0,   0, 0};

// Per-civilian-order-type map-improvement sprite class (short table at 0x697040).
short g_anMapImprovementSpriteClassByOrderType[9] = {2, 3, 1, 6, 0, 7, 5, 4, 8};

// Per-fort-level attacker penalty percent (int table at 0x695568); indexed by
// Province::fortLevel03.
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
// GLOBAL: IMPERIALISM 0x00651030
int g_UniversityRequirementResourceTypeTable[30] = {3,  4,  21, 22, -1, -1, -1, -1, 0,  17,
                                                    18, -1, 2,  -1, -1, -1, -1, -1, -1, -1,
                                                    1,  20, -1, -1, 19, -1, -1, -1, -1, -1};
// Per-resourceType "requires tiered nibble" boolean flag table. Read by the same function
// above; only nonzero-ness is consumed there.
unsigned char g_abResourceTypeUsesHighNibbleFlag[24] = {0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Per-resourceType capability-category code. Read by FindMaxResourceCapabilityValueForTile
// (0x513720).
unsigned char g_abResourceTypeCapabilityCategory[24] = {0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Third binary copy of the same per-resourceType flag pattern (the linker kept three);
// this one gates whether the mini-civ row (0x4ab970) and civ report name a tile edge's
// resource type in their "improvable resources" text.
// GLOBAL: IMPERIALISM 0x006963e8
unsigned char g_abResourceTypeMiniCivMentionFlag[24] = {0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0,
                                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0};
// Per-resourceType required-order-type code. Read by
// SeedRecruitSearchVisitedStateByCapabilityThresholdAlt (0x515890).
short g_anResourceTypeRequiredOrderType[24] = {2, 5, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2, 2, 6, 5, -1, -1, 0};
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

// Navy/order composite score table (0x550b60 /
// ComputeNavyOrderPriorityContributionPercentByCategory family); see TNavyOrderResourceDescriptor
// in global_data_tables.h.
TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[14] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0},
    {0, 0, 100, 0, 600, 0, 0, 2, 0, -1, 1, 0, 0, 0},
    {0, 0, 95, 0, 1000, 0, 0, 4, 0, -1, 1, 0, 0, 0},
    {300, 5, 90, 0, 900, 0, 4, 0, 0, 1, 3, 0, 1, 0},
    {600, 6, 80, 0, 1700, 0, 3, 0, 0, 0, 2, 0, 1, 0},
    {0, 0, 95, 0, 900, 0, 0, 8, 0, -1, 1, 0, 0, 0},
    {0, 0, 100, 0, 600, 0, 0, 4, 0, -1, 1, 0, 0, 0},
    {300, 7, 80, 0, 700, 0, 7, 0, 0, 2, 5, 0, 2, 0},
    {500, 8, 45, 0, 1200, 0, 5, 0, 0, 3, 3, 0, 2, 0},
    {1000, 10, 40, 0, 1800, 0, 6, 0, 0, 0, 4, 0, 3, 0},
    {0, 0, 75, 0, 1200, 0, 0, 16, 0, -1, 1, 0, 0, 0},
    {600, 9, 50, 0, 1000, 0, 8, 0, 0, 1, 6, 0, 3, 0},
    {2000, 13, 30, 0, 2800, 0, 7, 0, 0, 3, 5, 0, 4, 0},
    {1800, 13, 45, 0, 2200, 0, 9, 0, 0, 2, 6, 0, 4, 0}};

// Per-category (0..3) capability metric baseline averages, recomputed at runtime by
// RecomputeGlobalCapabilityAverages (0x54fd50) and read back as the normalization divisor
// by the navy/map-order per-category scoring helpers (0x5501b0, 0x550090, 0x54ff00).
// GLOBAL: IMPERIALISM 0x006a3ec8
int g_aCategoryMetricBaselineAverage[4] = {0};

// Mission score normalization divisor used by the control-sea-zone and blockade-port
// mission scoring helpers.
// GLOBAL: IMPERIALISM 0x0065a9c0
float g_fMissionScoreNormalizationDivisor = 5000.0f;

// Initial/reset score for TScatteredShipsMission.
// GLOBAL: IMPERIALISM 0x0065a9c8
float g_fScatteredShipsMissionDefaultScore = 0.001f;

// Per-nation output caches for RecomputeNationOrderPriorityMetrics (0x53fe30).
// Shared counters selecting the initial one-third offer and later one-half offers for
// the arms personality's basic and advanced resource groups.
// GLOBAL: IMPERIALISM 0x006a3a54
short g_nArmsBasicResourceOfferSplitCount_006a3a54 = 0;
// GLOBAL: IMPERIALISM 0x006a3a58
short g_nArmsAdvancedResourceOfferSplitCount_006a3a58 = 0;
// GLOBAL: IMPERIALISM 0x006a3a88
float g_afNationOrderQueueDivergence_006a3a88[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3ac0
float g_afNationOrderQueueDivergenceMirror_006a3ac0[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3ae0
float g_afNationMobileUnitDivergence_006a3ae0[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3b20
float g_afNationWeightedMilitaryOrderScore_006a3b20[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3b50
float g_afNationCombinedUnitDivergence_006a3b50[7] = {0};
// GLOBAL: IMPERIALISM 0x006a3b88
float g_afNationMobileUnitScore_006a3b88[7] = {0};

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
unsigned char g_bPerfectNavalIntelligenceCheat = 0;

MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32] = {0};

// Defend-province / mission priority-vector normalization (0x53e6e0 / 0x53ea70 family).
// GLOBAL: IMPERIALISM 0x0065a8f0
extern const float g_AttackProvinceMissionReadinessThreshold_0065A8F0 = 1.0f;
// GLOBAL: IMPERIALISM 0x0065a8f8
extern const float g_DefendProvinceMissionCrossSupportFloorScale_0065A8F8 = 0.8f;
// GLOBAL: IMPERIALISM 0x0065a8fc
extern const float g_MissionResourceWeightScale_0065A8FC = 1.1f;
// GLOBAL: IMPERIALISM 0x0065a900
extern const float g_BlockadePortMissionThreatFloor_0065A900 = 10.0f;
// GLOBAL: IMPERIALISM 0x0065a904
extern const float g_BlockadePortMissionThreatScale_0065A904 = 0.5f;
// GLOBAL: IMPERIALISM 0x0065a958
extern const float g_NavyMissionQueuedWeightDeficitScale_0065A958 = 1.0f;
// GLOBAL: IMPERIALISM 0x0065a95c
extern const float g_InvadeMissionSuppressedPriorContributionScale_0065A95C = 0.0f;
// GLOBAL: IMPERIALISM 0x0065a960
extern const float g_NavyMissionSimilarityExcessBlend_0065A960 = 0.25f;
// GLOBAL: IMPERIALISM 0x0065a968
// Difficulty-row / fort-level-column resource scaling for attack-province missions.
extern const float g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel_0065A968[5][4] = {
    {1.9f, 2.3f, 2.5f, 2.7f},
    {1.9f, 2.3f, 2.5f, 2.7f},
    {2.0f, 2.3f, 2.5f, 2.7f},
    {2.1f, 2.3f, 2.5f, 2.7f},
    {2.3f, 2.5f, 2.7f, 2.9f}};
// GLOBAL: IMPERIALISM 0x0065a9b8
extern const float g_MissionPositiveFallback_0065A9B8 = 1.0f;
// GLOBAL: IMPERIALISM 0x0065a9bc
extern const float g_Recompute_Nation_Order_LookupTable_0065A9BC = 0.05f;
// GLOBAL: IMPERIALISM 0x0065a9c4
extern const float g_Recompute_Nation_Order_LookupTable_0065A9C4 = -1000.0f;
// GLOBAL: IMPERIALISM 0x0065a9e8
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8 = 0.0f;
// GLOBAL: IMPERIALISM 0x0065a9e0
extern const double g_Recompute_Nation_Order_LookupTable_0065A9E0 = -1.0;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0 = 0.0;
double g_Recompute_Nation_Order_LookupTable_0065A9F8 = 0.01;
double g_Recompute_Nation_Order_LookupTable_0065AA00 = 0.5;
double g_Recompute_Nation_Order_LookupTable_0065AA08 = 1.0;
// GLOBAL: IMPERIALISM 0x0065aa10
extern const double g_PortZoneFriendlyMissionScoreMultiplier_0065AA10 = 1.5;
// GLOBAL: IMPERIALISM 0x0065aa18
extern const double g_PortZoneForeignMissionScoreMultiplier_0065AA18 = 1.25;
// GLOBAL: IMPERIALISM 0x0065aa20
extern const float g_Recompute_Nation_Order_LookupTable_0065AA20 = 139069760.0f;
// GLOBAL: IMPERIALISM 0x0065aa24
extern const float g_MissionEmptyResourceWeight_0065AA24 = 100.0f;
// GLOBAL: IMPERIALISM 0x0065aa48
extern const double g_ArmyMissionEligibleUnitStrengthScale_0065AA48 = 0.002;
// GLOBAL: IMPERIALISM 0x00697870
// Tactical composition reference profiles (4 rows x 5 action classes, shorts at
// 0x697870): row 0 baseline, row 1 fort-siege, row 2 open-field, row 3 unattributed.
// Consumed by the distribution-similarity scorer (0x5362c0) callers.
short g_awTacticalCompositionReferenceProfiles_00697870[20] = {
    40, 27, 0, 17, 16, 27, 36, 0, 17, 20, 26, 31, 20, 23, 0, 40, 22, 0, 38, 0};
// 4 back-to-back 4-entry target-percentage profiles consumed by distinct navy-order
// divergence-score callers: [0..3] NormalizeFourComponentNavyVector's callers, [4..7]
// TNavyMission::ComputeOrderDistributionSimilarityScoreForZone, [8..15] two further
// profiles used by sibling scorers in this same cluster.
short g_Populate_Beachhead_Mission_LookupTable_00697958[0x10] = {40, 40, 20, 0,  40, 30, 30, 0,
                                                                 35, 35, 0,  30, 0,  20, 80, 0};
const short g_NavyOrderDistributionCategoryWeights_00697978[4] = {40, 30, 30, 0};
// GLOBAL: IMPERIALISM 0x006978c8
extern const float g_MissionOrderDistanceDecayWeightTable_006978c8[6] = {1.0f,   0.8f,    0.64f,
                                                                         0.512f, 0.4096f, 0.32768f};

// Army-mission order-priority weight/scoring tables (0x53c620 / 0x53ceb0 /
// 0x53d4a0 family). Sizes are the minimum proven by observed index use;
// g_ArmyMissionCandidateScoreTable_006978f8's row count (state08 range) is
// not yet fully catalogued.
float g_ArmyMissionDotProductWeights_00697980[5] = {0};
float g_ArmyMissionCandidateScoreTable_006978f8[48] = {0};

// GLOBAL: IMPERIALISM 0x0065aa30
extern const double g_BeachheadMissionPriorityNormalization_0065AA30 = 100.0;

// Random-roll scaling constants for TAutoGreatPower::AssignNeedSlotFromSourceSlot19C
// (0x004e7680): 1/255 and 32767.
double g_DAT_00653fc0_Value_00653FC0 = 0.00392156862745098;
double g_DAT_00653fc8_Value_00653FC8 = 32767.0;

// Case-16 advisory mission acceptance thresholds, indexed by the defense minister's
// skillIndexC row and the mission tier column (0 attack, 1 amass, 2 invade,
// 3 defend, 4 blockade, 5 unused). Read by 0x004e9a50.
float g_afAdvisoryMissionTierThresholdByMinisterSkill_00653F18[5][6] = {
    {1.5f, 1.5f, 2.5f, 0.0f, 2.25f, 2.0f},  {1.75f, 1.75f, 2.5f, 0.0f, 2.25f, 2.25f},
    {2.0f, 2.0f, 2.0f, 0.0f, 1.5f, 1.5f},   {2.0f, 2.0f, 3.0f, 0.0f, 2.0f, 2.0f},
    {1.5f, 1.5f, 2.5f, 0.0f, 1.75f, 1.75f},
};

// TAutoGreatPower slot 0x9d / 0xa7 scoring constants: -100.0f and 0.5 (double).
float g_Compute_Advisory_Map_Value_00653FD4 = -100.0f;
double g_Evaluate_Advisory_Case11_Value_00653FD8 = 0.5;
extern const float g_Compute_Advisory_Zero_00653FD0 = 0.0f;
double g_Compute_Advisory_MinusSix_00653FE8 = -6.0;
double g_Compute_Advisory_MinusHundred_00653FF0 = -100.0;
// Float twin of the -6.0 double above (metric-4 denominator in 0x004e8750).
float g_Compute_Advisory_MinusSixFloat_00653FF8 = -6.0f;
double g_Compute_Advisory_Hundred_00654000 = 100.0;
double g_Compute_Advisory_OnePointFive_00654008 = 1.5;

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's city stock block by TGreatPower slot 0x39 (0x004df810).
short g_Rebuild_Primary_Nation_Value_00653570[6][0x17] = {
    {20, 20, 40, 30, 30, 10, 0, 20, 20, 20, 20, 20, 0, 10, 10, 10, 10, 10, 5, 0, 5, 0, 0},
    {5, 5, 10, 5, 5, 2, 0, 20, 10, 15, 8, 10, 0, 5, 5, 0, 0, 10, 5, 0, 5, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 20, 10, 24, 8, 19, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 26372, 105, 24, 0, -1, 0, 4281, 64, -29032, 100, 0, 0, 26360, 105, 148, 0, -1, 0, 14166, 64, 20152, 105}};

// Shared empty-text pointer passed by value as the modal's byval CString message seed
// (TViewMgr::BuildAndShowTurnOverlayByMode tail, 0x5d67fc).
// GLOBAL: IMPERIALISM 0x0066f050
char* g_pNationInfoEmptyText_0066f050 = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x0066f058
short g_anAbilityStatusPictureIndex_0066F058[29] = {0,  1,  3,  2,  7,  5,  6,  9,  10, 4,
                                                    8,  16, 12, 19, 22, 11, 17, 13, 14, 21,
                                                    15, 18, 26, 20, 23, 28, 24, 25, 27};

// Season-dependent sfx offset word: the nation-info modal plays sfx 0xbb8 + this value
// for overlay mode 5 (0x5d61f0).
// GLOBAL: IMPERIALISM 0x0066f0a6
short g_overlaySfxSeasonWord_0066f0a6 = 10;

// Advisor-newspaper list-building literals (TNewspaperView cluster).
// GLOBAL: IMPERIALISM 0x00695760
char g_szListSeparator_00695760[] = ", ";
// GLOBAL: IMPERIALISM 0x00698494
char g_szPlusPrefix_00698494[] = "+";
// GLOBAL: IMPERIALISM 0x00698498
char g_szListConjunction_00698498[] = " and ";

// GLOBAL: IMPERIALISM 0x0066fad0
double DAT_0066fad0 = 0.092;

} // extern "C"

#include "game/TZone.h"
#include "game/TOcean.h"
#include "game/TTaskForce.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TCivMgr.h"
#include "game/TSoundPlayer.h"

// Named global pointers read with a direct absolute load in the original (vs the
// ReadGlobalPointer(imm) shortcut, which emits an extra indirection that cannot pair).
// Defined outside extern "C" so they keep C++ linkage and match typed header declarations.
// Tactical unit sprite facing-offset table: [unit type 0..28][orientation 0..6][side 0..1]
// pixel deltas OffsetRect-applied to the sprite rect for units on a fresh trench-deploy
// tile (reader: TTacticalBattleView::ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset,
// filler: InitializeTacticalUnitFacingOffsetTable, a CRT static initializer in the original).
// GLOBAL: IMPERIALISM 0x006a4780
POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

// Const pointer to the shared empty-string byte (seeds the advisory message
// accumulators in THelpMgr::DispatchTurnStateSpecialAdvisoriesAndReturnCount).
// GLOBAL: IMPERIALISM 0x00656f60
extern const char* const g_pszEmptyTextPointer_00656f60 = g_szEmptyString;

TZone* g_pMapActionContextListHead = 0;
// GLOBAL: IMPERIALISM 0x006a3fbc
TOcean* g_pActiveMapOrderContext = 0;
TMapMgr* g_pGlobalMapState = 0;
TCivMgr* g_pSelectedCivilianOrderState = 0;
// Seed viewport offsets copied into TWorldView::viewportOrigin60.x/Y by the TOceanDialog
// ctor (0x565e90). Only known writer is the reset helper at 0x56a3b0 (`xor eax,eax;
// mov [6a3ff0],eax; mov [6a3ff4],eax; ret`), which zeroes both.
// GLOBAL: IMPERIALISM 0x006a3ff0
int g_nOceanDialogSeedViewportOffsetX = 0;
// GLOBAL: IMPERIALISM 0x006a3ff4
int g_nOceanDialogSeedViewportOffsetY = 0;
// Map-dialog viewport width in staggered tile columns. The BSS-backed value is seeded by
// InitializeMapDialogViewportTileSpan (0x519970) before WinMain.
// GLOBAL: IMPERIALISM 0x006a33b0
int g_wMapDialogViewportTileSpan;
// GLOBAL: IMPERIALISM 0x0065c2f0
short g_awMapContextActionLabelTokenByCommand[17] = {0,     0x3f0, 0x3f2, 0x3f2, 0x3f2, 0x3f2,
                                                     0x3f2, 0x3f2, 0x3f2, 0x3f1, 0x3f3, 0x3f3,
                                                     0x3f6, 0x3f8, 0x3f4, 0x3f5, 0x3f7};
// Per-tech prerequisite pair (tech ids; 0 = none). Indexed by tech id in
// TTechMgr::AreTechItemPrerequisitePairCompleted / SelectMissingTechItemPrerequisitesFromPair
// (0x5b0a20/0x5b0a90). 34 entries; ends where the CRuntimeClass at 0x66ac98 begins.
// Per-tech research cost in gold, indexed by tech id (readers: 0x5b12e0 buy-button label,
// TTechItemView::DoEvent 0x5b1e20).
// GLOBAL: IMPERIALISM 0x0066ad58
int g_anTechItemResearchCostByTechId[29] = {
    0,     0,     1000,  1000,  1500,  1500,   1500,   1500,   3000,  3000,
    3000,  6000,  7000,  10000, 12000, 12000,  12000,  12000,  12000, 25000,
    20000, 40000, 40000, 40000, 40000, 100000, 120000, 150000, 150000};
// Per-ability unit-order cost profile, one row per ability id, columns matching
// TUnitOrder::SetOrderCostProfile's parameters: {resourceTypeIndex,
// primaryInputResourceId, primaryInputPerUnit, secondaryInputResourceId,
// secondaryInputPerUnit, cashCostPerUnit, workforceMode}.
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
short g_aTechItemPrerequisitePairs[34][2] = {
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
TTradeMgr* g_pNationInteractionStateManager = 0;
// GLOBAL: IMPERIALISM 0x006a4220
CString g_cstrCountryNameSettingValue006A4220;
// GLOBAL: IMPERIALISM 0x006a4268
TSetupRandomMapPicture* g_pActiveRandomMapSetupPicture006A4268 = 0;

extern "C" {
short g_awEngineerFortBuildCostByLevel[8] = {5000, 7500, 10000, 0, 0, 100, 0, 1000};
int g_adwEngineerRailBuildCostByTerrainType[16] = {100, 150, 200, 400, 300, 0, 150, 100, 6907540, 12, 65535, 4229325, 6901432, 0, 0, 1066401792};
// Civilian work-order rescind refund by cost class (nibble from
// GetTileCivilianWorkOrderCostClassNibble); -1 entries are unused classes.
int g_adwCivilianWorkOrderCostByClass[16] = {100, 1000, 5000, -1, -1, -1, 0, 1,
                                             -1,  -1,   2,    3,  4,  -1, 5, 6};

int g_nMapActionContextCount = 0;
void* g_pMapActionContextDistanceCache = 0;
// Count g_pMapActionContextDistanceCache was last sized for (0x006984b4); cache is
// rebuilt whenever g_nMapActionContextCount no longer matches this.
int g_nMapActionContextDistanceCacheSizedFor = -1;

// GLOBAL: IMPERIALISM 0x006a42dc
unsigned char g_bRandomMapDeveloperCheatFlag = 0;
// Developer-cheat probe filename: TSimMgr::InitializeTurnFlowStateDefaults (0x57bc2d)
// stats a file literally named "Conan" via CFile::GetStatus.
// GLOBAL: IMPERIALISM 0x00698bec
char g_szConanCheatFileName_00698BEC[] = "Conan";

// Trade-item dispatch order consumed by
// TTradeMgr::InitializePendingDiplomacyTransferCursorAndProcess (0x5b9190). Values
// are read directly from the original rdata table.
// GLOBAL: IMPERIALISM 0x0066d810
short g_aTradeDealCategoryOrder_0066D810[0x11] = {13, 14, 15, 16, 7, 8, 9, 10, 11,
                                                  12, 0,  1,  2,  3, 4, 5, 6};
// Multiplicative identity used by TTradeMgr::Power.
// GLOBAL: IMPERIALISM 0x0066d8e0
extern const double g_TradePowerIdentity_0066D8E0 = 1.0;

// Initial price for each of the 17 trade-item categories.
// GLOBAL: IMPERIALISM 0x0069a910
extern const short g_aTradeItemBasePriceByCategory_0069A910[0x11] = {
    100, 100, 100, 100, 100, 300, 100, 100, 300, 300, 300, 300, 300, 900, 900, 900, 900};

// 17 four-char control tags (space + digit + 2-letter category: "sr" raw materials 0-6,
// "am" manufactured 0-5, "dg" 0-3), walked by TTradeScreenPicture::Draw to
// resolve each commodity summary-row control. Stored little-endian as the in-memory bytes.
// GLOBAL: IMPERIALISM 0x0066dad0
const unsigned int g_tradeCommodityRowTagTable[17] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320};

// GLOBAL: IMPERIALISM 0x006a58c8
int g_defaultDropShadowTextColor = 0;
// 26 (start, end) capability-priority range pairs walked by
// TTechMgr::GenerateRandomCapabilityPrioritySlots. The reccmp symbol points at pair 0's END
// value; pair 0's START value (1) lives one short earlier and is read via cursor[-1].
// GLOBAL: IMPERIALISM 0x0066aba6
short g_anCapabilityPriorityRangePairs[53] = {
    5,  6,  10, 6,  10, 6,  10, 6,  10, 11, 15, 11, 15, 16, 20, 21, 25, 21,
    25, 26, 30, 26, 30, 31, 35, 31, 35, 36, 40, 41, 45, 41, 45, 46, 50, 51,
    55, 56, 60, 56, 60, 56, 60, 61, 65, 61, 65, 66, 70, 66, 70, 0,  0};
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
// GLOBAL: IMPERIALISM 0x006973d0
extern "C" const char s_SourcePathUMapDlog_006973D0[] = "D:\\Ambit\\Cross\\UMapDlog.cpp";
// GLOBAL: IMPERIALISM 0x00698470
extern "C" const char s_SourcePathUNewspaper_00698470[] = "D:\\Ambit\\Cross\\UNewspaper.cpp";
// GLOBAL: IMPERIALISM 0x00698040
extern "C" const char s_SourcePathUMultiplayerMgr_00698040[] =
    "D:\\Ambit\\Cross\\UMultiplayerMgr.cpp";
// GLOBAL: IMPERIALISM 0x006983c8
extern "C" const char s_SourcePathUNavy_006983C8[] = "D:\\Ambit\\Cross\\UNavy.cpp";
// GLOBAL: IMPERIALISM 0x00699ff4
extern "C" const char s_SourcePathUTacViews_00699FF4[] = "D:\\Ambit\\Cross\\UTacViews.cpp";
// GLOBAL: IMPERIALISM 0x0069b740
extern "C" const char s_SourcePathUViewMgrMore_0069B740[] = "D:\\Ambit\\Cross\\UViewMgr.more.cpp";
// GLOBAL: IMPERIALISM 0x00696c58
extern "C" const char s_SourcePathUHelpMgr_00696C58[] = "D:\\Ambit\\Cross\\UHelpMgr.cpp";
// GLOBAL: IMPERIALISM 0x00696860
extern "C" const char s_SourcePathUDefenseMinister_00696860[] =
    "D:\\Ambit\\Cross\\UDefenseMinister.cpp";
// GLOBAL: IMPERIALISM 0x0069573c
extern "C" const char s_SourcePathUArmyMgr_0069573C[] = "D:\\Ambit\\Cross\\UArmyMgr.cpp";
// GLOBAL: IMPERIALISM 0x006962e8
extern "C" const char s_SourcePathUCityDialogs_006962E8[] = "D:\\Ambit\\Cross\\UCityDialogs.cpp";
// GLOBAL: IMPERIALISM 0x00696d68
extern "C" const char s_SourcePathUMacViewMgr_00696D68[] = "D:\\Ambit\\Cross\\UMacViewMgr.cpp";
// GLOBAL: IMPERIALISM 0x00696310
extern "C" const char g_szCityProductionUniversityPrefix[] = "University: ";
// GLOBAL: IMPERIALISM 0x00696320
// The original data symbol spans through the aligned start of the following string,
// so preserve those four leading "Ship" bytes in its raw extent as well.
extern "C" const char g_szCityProductionArmoryPrefix[16] = {
    'A', 'r', 'm', 'o', 'r', 'y', ':', ' ', '\0', '\0', '\0', '\0', 'S', 'h', 'i', 'p'};
// GLOBAL: IMPERIALISM 0x0069632c
extern "C" const char g_szCityProductionShipyardPrefix[] = "Shipyard: ";
// GLOBAL: IMPERIALISM 0x0069a7f8
extern "C" const char s_SourcePathUTestDialogs_0069A7F8[] = "D:\\Ambit\\Cross\\UTestDialogs.cpp";
extern "C" const char s_SourcePathUCityViews_00696650[] = "D:\\Ambit\\Cross\\UCityViews.cpp";
extern "C" const char s_SourcePathUArmyViews_00695858[] = "D:\\Ambit\\Cross\\UArmyViews.cpp";
extern "C" const char s_SourcePathUOceanViews_00698650[] = "D:\\Ambit\\Cross\\UOceanViews.cpp";
// GLOBAL: IMPERIALISM 0x00696ae0
extern "C" const char s_SourcePathUDiplomacyViews_00696AE0[] =
    "D:\\Ambit\\Cross\\UDiplomacyViews.cpp";
// GLOBAL: IMPERIALISM 0x006964b0
extern "C" const char s_SourcePathUCityMinister_006964B0[] = "D:\\Ambit\\Cross\\UCityMinister.cpp";
// GLOBAL: IMPERIALISM 0x0069943c
extern "C" const char s_SourcePathUSuperMap_0069943C[] = "D:\\Ambit\\Cross\\USuperMap.cpp";
// GLOBAL: IMPERIALISM 0x0069aa94
extern "C" const char s_SourcePathUTradeViews_0069AA94[] = "D:\\Ambit\\Cross\\UTradeViews.cpp";
// GLOBAL: IMPERIALISM 0x006984cc
extern "C" const char s_SourcePathUOcean_006984CC[] = "D:\\Ambit\\Cross\\UOcean.cpp";
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

// GLOBAL: IMPERIALISM 0x00698ee0
extern "C" int g_anArmyToolbarCategoryByUnitType[30] = {
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9};

// GLOBAL: IMPERIALISM 0x698f58
extern "C" short g_anTargetTileProfileByCivilianClassAndSlot[45] = {
    8,  9, -1, -1, -1, 8,  9,  10, 11, 12, 6,  5, 2,  -1, -1, 13, -1, -1, -1, -1, -1, -1, -1,
    -1, 0, 3,  7,  -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, 0,  10, 11, 12, -1, -1};

// GLOBAL: IMPERIALISM 0x00698ab0
int g_nRandomMapSelectedNationSlot00698AB0 = -1;
// GLOBAL: IMPERIALISM 0x00698ae0
char g_szCountryNameProfileKey00698AE0[] = "CountryName";

// Turn-flow cooldown defer counter and side flag (IsTurnCooldownCounterActiveOrResetFlag).
// GLOBAL: IMPERIALISM 0x006a43c4
short g_nTurnCooldownDeferCounter006A43C4 = 0;
// GLOBAL: IMPERIALISM 0x006a43c0 — set once scenario/turn-flow bootstrap completes.
char g_bTurnFlowBootstrapComplete = 0;
// GLOBAL: IMPERIALISM 0x006a43f0 — nonzero during multiplayer scenario setup.
char g_bMultiplayerScenarioSetupActive = 0;
// GLOBAL: IMPERIALISM 0x00698b10
short g_nTurnCooldownSideFlag00698B10 = 1;

// Per-nation setup defaults copied into TSimMgr by the ctor and reset path. The old
// model incorrectly anchored a 27-short array one element into this table and filled
// it with unrelated address-like values. The original is seven complete four-short
// rows beginning at 0x698b18.
// GLOBAL: IMPERIALISM 0x00698b18
extern "C" short g_aDefaultNationSetupPolicyProfiles[7][4] = {
    {1, 2, 3, 3}, {2, 2, 5, 2}, {2, 1, 4, 1}, {2, 3, 3, 3},
    {2, 3, 2, 4}, {2, 2, 1, 3}, {2, 0, 4, 0}};

// Debug/trace tag literal passed to TSimMgr::RebuildMapContextAndGlobalMapState
// (0x0057c7c0) from case 3 of AdvanceGlobalTurnStateMachine.
// GLOBAL: IMPERIALISM 0x00698c0c
extern "C" const char s_Chunk_00698C0C[] = "Chunk";

// UI default text-style/command-param block copied into every TControl (the 10-byte
// dual-view region at offsets 0x78-0x81); same TextStyle shape the
// widgets carry. Named so reccmp pairs the direct absolute loads in the TControl ctor.
TextStyle g_UiResourceEntryDefaultTextStyle = {0, 0, 0, 0};

} // extern "C"

// GLOBAL: IMPERIALISM 0x0066db50
const char* g_cstrTradeTotalsBalanceSubstitution0066DB50 = g_szEmptyString;

#include "game/TWNetSessionManager.h"

// UGameWindow/dialog-factory widget build stack. The list element type is TView*: its
// vtable family uses the CList<TView*,TView*> serializer/destructors, not the WNet
// CList<void*,void*> copies below.
// GLOBAL: IMPERIALISM 0x006a13e0
CList<TView*, TView*> g_UiWidgetBuildStack006a13e0;

// WNetMgr.cpp file-scope statics; g_ptNetworkModalMessage006a5ed8 is the POINT passed
// to TViewMgr::ModalMessage, while g_WNetPendingPacketList006a5f40 is the
// local-player pending-packet queue that TNetMgr::Send appends heap packet copies to
// (block size 10, per the original static-init at 0x5e26d0).
// GLOBAL: IMPERIALISM 0x006a5ed8
POINT g_ptNetworkModalMessage006a5ed8 = {0, 0};
// GLOBAL: IMPERIALISM 0x006a5f10
CArray<void*, void*> g_WNetSerializedPtrArrayA006a5f10;
// GLOBAL: IMPERIALISM 0x006a5f28
CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_WNetSerializedPtrArrayB006a5f28;
// GLOBAL: IMPERIALISM 0x006a5f40
CList<void*, void*> g_WNetPendingPacketList006a5f40(10);

// Suppresses the WNetMgr.cpp assertion for an unknown DirectPlay system-message code.
// GLOBAL: IMPERIALISM 0x006a6020
int g_suppressUnexpectedDirectPlaySystemMessageAssert006a6020;

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

// TEMPLATE: IMPERIALISM 0x005e4830
// ?Serialize@?$CArray@PAXPAX@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x005e4a30
// ??_G?$CList@PAXPAX@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x005e4780
// ??0?$CArray@PAXPAX@@QAE@XZ

// TEMPLATE: IMPERIALISM 0x005e47b0
// ??1?$CArray@PAXPAX@@UAE@XZ

// DirectPlay session manager object embedded at a fixed address (not a pointer).
// GLOBAL: IMPERIALISM 0x006a5f60
TWNetSessionManager g_NetworkSessionManager006a5f60;

// DirectPlay application identity written into DPSESSIONDESC2 before host/join enumeration.
// GLOBAL: IMPERIALISM 0x0066f968
const GUID g_ImperialismDirectPlayApplicationGuid0066f968 = {
    0xc55dc2ef, 0xfd3e, 0x11d0, {0xbc, 0x16, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};

// Heap-owned runtime selection records used by the DirectPlay session chooser.
// This TU's CArray specialization has vtable 0x00646fb0 and ctor 0x00480b20.
// GLOBAL: IMPERIALISM 0x006a15e0
CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_RuntimeSelectionRecords006a15e0;

// Compiler-emitted methods for this TU's RuntimeSelectionRecord pointer-array
// specialization. The source implementation is the retail MFC CArray template.
// TEMPLATE: IMPERIALISM 0x00480b20
// ??0?$CArray@PAURuntimeSelectionRecord@@PAU1@@@QAE@XZ

// TEMPLATE: IMPERIALISM 0x00480b50
// ??1?$CArray@PAURuntimeSelectionRecord@@PAU1@@@UAE@XZ

// TEMPLATE: IMPERIALISM 0x00480bd0
// ?Serialize@?$CArray@PAURuntimeSelectionRecord@@PAU1@@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x00480dd0
// ??_G?$CArray@PAURuntimeSelectionRecord@@PAU1@@@UAEPAXI@Z

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
// 4-byte flag (written as a dword by TStatusButton::DoEvent); BOOL-style int.
int g_bCityDialogLegendSelectionInitialized = 0;

// Per-type index into TShipView::Draw's 8-entry order-status
// string pool (GetString group 0x2760); -1 = no status line for that resource type
// (verified via `just ghidra-read-data 0x65c7f8 dword 14`; the table ends there --
// the next dword looks like unrelated pointer data, matching
// g_NavyOrderResourceDescriptorTable's 14-entry type domain).
// GLOBAL: IMPERIALISM 0x0065c7f8
const int g_ShipOrderStatusStringIndexByResourceType_0065c7f8[14] = {
    -1, -1, -1, 0, 1, -1, -1, 2, 3, 4, -1, 5, 6, 7,
};

// Per-type horizontal source offset in TNavyRoster's 0xdba bitmap atlas.
// GLOBAL: IMPERIALISM 0x006985e8
const short g_ShipRosterAtlasHorizontalOffsetByResourceType_006985E8[14] = {
    0, 0, 0, 0, 160, 0, 0, 320, 480, 640, 0, 800, 960, 1120,
};

// Palette entries used to color ocean-map previews by their owning nation tag.
// GLOBAL: IMPERIALISM 0x006985b8
const unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24] = {
    0xf3, 0x2a, 0x25, 0x1d, 0xf6, 0x8c, 0xbd, 0x0a, 0x0b, 0x0d, 0x29, 0xde,
    0xdf, 0xfa, 0x2c, 0x31, 0x33, 0x41, 0x48, 0xd0, 0xcd, 0xce, 0xcf, 0x00,
};

// The four one-reader feature bytes bracket the ocean overview's optional route,
// labeling, and final surface-transfer passes. All are enabled in the retail image.
// GLOBAL: IMPERIALISM 0x0069859c
const unsigned char g_bDrawOceanRouteOverlay = 1;
// GLOBAL: IMPERIALISM 0x006985ac
const unsigned char g_bTransferOceanViewportToActiveSurface = 1;
// GLOBAL: IMPERIALISM 0x006985b0
const unsigned char g_bDrawOceanZoneLabels = 1;
// GLOBAL: IMPERIALISM 0x006985b4
const unsigned char g_bDrawOceanNationLabels = 1;

// Border/transition colors paired with the owner-fill table immediately above.
// GLOBAL: IMPERIALISM 0x006985d0
const unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24] = {
    0x15, 0x2d, 0x1e, 0x1c, 0x30, 0xae, 0xca, 0x7d, 0x7d, 0x7d, 0x7d, 0xe2,
    0xe2, 0xe2, 0xe2, 0x51, 0x51, 0x51, 0x51, 0xf0, 0xf0, 0xf0, 0xf0, 0x00,
};

// GLOBAL: IMPERIALISM 0x006a590c
TInfoBarText* g_pCursorControlPanel = nullptr;

// Modal-message placement point used by TDisplayMgr's forwarding slot. The original
// static initializer zeroes both coordinates independently.
// GLOBAL: IMPERIALISM 0x006a59e0
POINT g_ptControlStringModalMessage = {0, 0};

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
GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord = {0, {0, 0, 0, 0}};
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
POINT g_ptArmyOrderModalMessage = {0, 0};
// Modal-message placement used when no eligible secondary home-city tile exists.
// GLOBAL: IMPERIALISM 0x006a2c18
POINT g_ptCityInteriorMinisterModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a3180
POINT g_ptNationComparisonModalMessage = {0, 0};
// GLOBAL: IMPERIALISM 0x006a5820
POINT g_ptTechItemModalMessage = {0, 0};
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

// Last turn tick for which ShowTurnAlertsForActiveNation (0x502b60) ran; the alert
// pass is skipped until the tick advances.
// GLOBAL: IMPERIALISM 0x006a31c0
int g_lastTurnAlertTick_006a31c0 = 0;

// Last map tile index the player clicked, stored by
// TWorldView::HandleMapTileClickSetOrderContextAndHandleEvent79 (0x5962a0).
// GLOBAL: IMPERIALISM 0x006a4608
int g_lastClickedMapTileIndex_006a4608 = 0;

// When set (and the modal's context tag is 2), overrides the computed 'GOLD' resource
// id in the nation-info modal (0x5d5ea6). Never observed written yet; zero-initialized.
// GLOBAL: IMPERIALISM 0x006a5bac
int g_nationInfoGoldResourceOverride_006a5bac = 0;

// Round-robin localization-audio slot cursor (0..5) advanced by
// TSoundPlayer::UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState (0x5e50c0).
// GLOBAL: IMPERIALISM 0x006a60f8
int g_localizationAudioSlotCursor_006a60f8 = 0;

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
// Per-unit-type weight table summed by TArmyMgr::ComputeWeightedNeighborLinkScore-
// ForNodeIndex (0x004a5aa0) over a tile's stationed military units.
int g_anWeightedNeighborUnitScoreByType_006955F0[32] = {
    70,  137, 135, 164, 165, 211,  193, 300, 95,  243, 230, 265, 230, 275, 323, 549,
    170, 450, 471, 495, 493, 1010, 715, 913, 193, 260, 360, 200, 200, 200, 0,   1000,
};

short g_anUnitTypeCombatCategoryByType00669858[32] = {
    0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// Per-unit-type base action-point word table (.rdata); TArmyTacUnit::
// GetBaseActionPoints (0x5a6120) returns this value for the unit's type.
// GLOBAL: IMPERIALISM 0x00669898
short g_awUnitTypeBaseActionPointTable[32] = {40, 60,  40, 40, 110, 90, 50, 30, 40, 60,  40,
                                              40, 110, 90, 60, 30,  50, 70, 50, 40, 110, 90,
                                              80, 30,  40, 40, 50,  90, 90, 90, 0,  0};

// The fifteen per-tile AI heuristic scorers as a member-function-pointer table
// (single-inheritance MSVC5 member pointers are plain code pointers in .data).
// GLOBAL: IMPERIALISM 0x006994c0
TacticalTileHeuristicScorerFn g_apfnTacticalTileHeuristicScorers_006994C0[15] = {
    &TArmyPlayer::ScoreTacticalTileHoldPositionBonus,                // [0]  0x59d6b0
    &TArmyPlayer::ScoreTacticalTileFireOpportunityAndTargetApproach, // [1]  0x59d6e0
    &TArmyPlayer::ScoreTacticalTileSapperWallApproachColumn,         // [2]  0x59d810
    &TArmyPlayer::ScoreTacticalTileAdjacentEnemyContact,             // [3]  0x59d8a0
    &TArmyPlayer::ScoreTacticalTileEnemyEngagementExposureCount,     // [4]  0x59d940
    &TArmyPlayer::ScoreTacticalTileRetreatEdgeRowProximity,          // [5]  0x59da20
    &TArmyPlayer::ScoreTacticalTileCoverTerrainBonus,                // [6]  0x59dac0
    &TArmyPlayer::ScoreTacticalTileAdjacentRallyTargetBonus,         // [7]  0x59db00
    &TArmyPlayer::ScoreTacticalTileDistanceFieldAdvance,             // [8]  0x59dba0
    &TArmyPlayer::ScoreTacticalTileFriendlyArtillerySpacing,         // [9]  0x59dbe0
    &TArmyPlayer::ScoreTacticalTileArtilleryFiringLaneColumn,        // [10] 0x59dcd0
    &TArmyPlayer::ScoreTacticalTileEnemyArtilleryExposureCount,      // [11] 0x59dd40
    &TArmyPlayer::ScoreTacticalTileEngageableEnemyStandoff,          // [12] 0x59de30
    &TArmyPlayer::ScoreTacticalTileEnemyArtilleryHuntBonus,          // [13] 0x59dfe0
    &TArmyPlayer::ScoreTacticalTileEnemyEdgeColumnZoneBonus,         // [14] 0x59e0d0
};

// Tactical AI cursor-mode ratio thresholds and projection factors (.rdata FP pool).
// GLOBAL: IMPERIALISM 0x00669508
double g_dTacticalCursorStrongRatioThreshold_00669508 = 3.0;
// GLOBAL: IMPERIALISM 0x00669510
double g_dTacticalCursorOverwhelmRatioThreshold_00669510 = 4.0;
// GLOBAL: IMPERIALISM 0x00669518
double g_dTacticalCursorWeakRatioThreshold_00669518 = 0.25;
// GLOBAL: IMPERIALISM 0x00669520
double g_dTacticalCursorArtilleryParityThreshold_00669520 = 1.0;
// GLOBAL: IMPERIALISM 0x00669528
double g_dTacticalCursorArtillerySuperiorityThreshold_00669528 = 1.8;
// GLOBAL: IMPERIALISM 0x00669530
double g_dTacticalCursorAssaultRatioThreshold_00669530 = 2.5;
// GLOBAL: IMPERIALISM 0x00669538
double g_dTacticalCursorRetreatRatioThreshold_00669538 = 0.8;
// Base-class default for TTacticalUnit::GetBaseAttackPower/GetDamageScale; derived unit
// types (TArmyTacUnit/TNavyTacUnit) override with real per-unit-type table lookups.
// KNOWN RESIDUAL: this value is genuinely 0.0f in the original. A zero-valued scalar
// global lands in .bss under this toolchain, which just datacmp flags as
// "(uninitialized)" against the original's on-disk 0.0 -- a data-section placement
// quirk, not a source defect (see the data-modeling skill's BSS field note). Tried and
// rejected: a literal `return 0.0f;` (moves the constant into the compiler's
// CRuntimeClass structure instead, a real call-target mismatch, strictly worse) and a
// raw `reinterpret_cast<const float*>(0x00669ec0)` address read (same established
// technique as TDefendProvinceMission.cpp's p_neg_one_/p_1_0_ locals, but reccmp still
// can't resolve the bare address to a clean symbol here). This named-global form is the
// only one of the three giving a 100% exact match on all four affected functions
// (TTacticalUnit/TArmyTacUnit/TNavyTacUnit x2); the residual is isolated to
// just datacmp-gate, which needs a maintainer-approved baseline update to clear.
// GLOBAL: IMPERIALISM 0x00669ec0
float g_fTacticalRetreatQualityWeightDefault_00669EC0 = 0.0f;
// GLOBAL: IMPERIALISM 0x00669ec8
double g_dTacticalQualityFactorStep_00669EC8 = -0.1;
// GLOBAL: IMPERIALISM 0x00669ed0
double g_dTacticalQualityFactorBase_00669ED0 = 1.0;
// GLOBAL: IMPERIALISM 0x00669f0c
float g_fTacticalStrengthProjectionScale_00669F0C = 0.002f;

// Direct-fire flag per unit CATEGORY CODE (.rdata floats; sibling of the 0x669830
// per-category copy, this one indexed by g_awTacticalUnitCategoryCodeBySlot values).
// GLOBAL: IMPERIALISM 0x00669390
float g_afTacticalDirectFireFlagByCategoryCode_00669390[10] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f,
                                                               1.0f, 0.0f, 0.0f, 1.0f, 1.0f};

// Per-unit-type tactical AI class (.rdata; duplicate values of the 0x669858 category
// table at a separate address): 0 infantry, 1 artillery-advance, 2 cavalry-screen,
// 3/4 support classes. Drives deployment strategy and the auto-turn controller.
// GLOBAL: IMPERIALISM 0x006693b8
short g_awTacticalUnitAiClassByUnitType_006693B8[32] = {
    0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// Per-unit-type action-point cost word (.rdata; duplicate values of the 0x669898
// base-action-point table): the sapper dig loop budgets against half of this.
// GLOBAL: IMPERIALISM 0x006693f8
short g_awTacticalUnitActionPointCostByType_006693F8[32] = {
    40, 60, 40, 40, 110, 90, 50, 30, 40, 60, 40, 40, 110, 90, 60, 30,
    50, 70, 50, 40, 110, 90, 80, 30, 40, 40, 50, 90, 90,  90, 0,  0};

// Tactical tile-selection heuristic weights per AI stance (.rdata): 19 rows of 15
// weights, one weight per tile-score heuristic; row index = TTacticalUnit AI stance
// (aiStateCode2c) or a strategy-specific row (12/13 sapper, 18 artillery hold).
// GLOBAL: IMPERIALISM 0x00699500
int g_anTacticalTileHeuristicWeightsByAiState_00699500[19][15] = {
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
    {0, 1, 0, 0, -100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

// Direct-fire flag per unit category (.rdata floats): 0.0 marks the indirect-fire
// categories 6/7 whose shots erode a fort wall they cross.
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

// Strategic ship type -> tactical navy unit type; -1 means the strategic type has no
// tactical representation.
// GLOBAL: IMPERIALISM 0x00669d80
int g_anTacticalNavyUnitTypeByShipType_00669D80[14] = {-1, -1, -1, 0,  1, -1, -1,
                                                       2,  3,  4,  -1, 5, 6,  7};

// Attack-power terrain modifier [category * 5 + tile terrainType0] (.rdata floats).
// GLOBAL: IMPERIALISM 0x00669ac8
float g_afTacticalAttackTerrainModifierByCategory[50] = {
    1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  1.0f,  1.0f,  1.0f,  0.0f, 1.0f,  0.75f, 0.75f,
    1.0f,  0.0f,  1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  1.0f,  1.0f, 1.0f,  0.0f,  1.0f,
    0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f, 0.75f, 0.75f, 1.0f,
    0.0f,  1.0f,  0.75f, 0.75f, 1.0f,  0.0f,  1.0f,  0.75f, 0.75f, 1.0f, 0.0f};

// Incoming-damage terrain modifier [defender category * 5 + terrainType0] (.rdata).
// GLOBAL: IMPERIALISM 0x00669b90
float g_afTacticalDefenseTerrainModifierByCategory[50] = {
    1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 0.8f, 0.8f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f,
    1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f,
    1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f,
    0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 0.0f};

// Cover damage modifier [defender category * 5 + cover state] where cover state is
// TacticalTileRecord::deployMark8 (1 = trench, 2..4 = fort-wall levels) (.rdata).
// GLOBAL: IMPERIALISM 0x00669c58
float g_afTacticalCoverDamageModifierByCategory[50] = {
    1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f,
    0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 1.0f, 0.7f, 0.6f, 0.5f, 1.0f,
    1.0f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f,
    0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f, 1.0f, 0.8f, 0.7f, 0.6f, 0.5f};

// Tactical move cost per unit category and tile terrain code (.rdata): 10 category
// rows x 5 terrain codes, in tenths of an action point band (999 = impassable).
// GLOBAL: IMPERIALISM 0x00669a60
short g_awTacticalMoveCostByCategoryAndTerrain[50] = {
    10,  20, 30,  15, 999, 10,  10, 10,  10, 999, 10,  20, 30,  15, 999, 10, 20,
    30,  15, 999, 10, 10,  10,  10, 999, 10, 20,  30,  15, 999, 10, 20,  30, 15,
    999, 10, 20,  30, 15,  999, 10, 20,  30, 15,  999, 10, 20,  30, 15,  999};

// Fort strength points per fort level (.rdata); seeds the 8 per-row-pair pools of a
// tactical battle in TArmyBattle::LoadBattleSetupTabDataByIndex (0x5a4fc0).
// GLOBAL: IMPERIALISM 0x00669818
int g_anFortStrengthPointsByFortLevel[6] = {0, 0, 500, 750, 1000, 0};

// Battle-setup terrain layout file-name template ("data/%%03d.tab").
// GLOBAL: IMPERIALISM 0x00699e20
extern "C" const char g_szBattleSetupTabPathFormat[] = "data/%03d.tab";

// Source-path string for UTacPlayer.cpp asserts.
// GLOBAL: IMPERIALISM 0x00699d84
extern "C" const char s_SourcePathUTacPlayer_00699D84[] = "D:\\Ambit\\Cross\\UTacPlayer.cpp";

// Empty-string pointer used by the battle-summary dialog builder (0x5a2750); points
// at g_szEmptyString.
// GLOBAL: IMPERIALISM 0x00669db8
const char* g_pszEmptyTextRef_00669db8 = g_szEmptyString;

// Paragraph separator between the two per-side casualty lines of the battle summary.
// GLOBAL: IMPERIALISM 0x00699438
extern "C" const char s_szDoubleNewline_00699438[] = "\n\n";

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
// fopen mode string (TLoadSavePicture.cpp). Linker-pooled with the same "rb" literal used
// as a flavor-text syllable in map_context_flavor_builders.cpp -- named after the literal
// value, not either consumer, since neither owns the address.
// GLOBAL: IMPERIALISM 0x00698720
char g_szLiteralRb_00698720[] = "rb";
// GLOBAL: IMPERIALISM 0x00698724
char g_szSaveDirectoryPrefix_00698724[] = "Save/";
// Autosave-slot display label (TLoadSavePicture.cpp). Linker-pooled with the same "A"
// literal used as a flavor-text syllable in map_context_flavor_builders.cpp -- named after
// the literal value, not either consumer, since neither owns the address.
// GLOBAL: IMPERIALISM 0x0069872c
char g_szLiteralA_0069872C[] = "A";
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
// Modal placement used for invalid/cross-session save-file warnings.
// GLOBAL: IMPERIALISM 0x006a2128
POINT g_ptSaveLoadErrorModalMessage = {0, 0};
// One-shot guard for TAmbitFileBasedDocument::SaveDocument's UAmbit.cpp assertion.
// GLOBAL: IMPERIALISM 0x006a21c4
int g_saveDocumentAssertGuard = 0;
// Default text returned for a null nation descriptor (points at g_szEmptyString).
// GLOBAL: IMPERIALISM 0x00653300
char* g_pszDescriptorDefaultName_00653300 = g_szEmptyString;
// GLOBAL: IMPERIALISM 0x006973c8
char g_szUiCloseParen_006973C8[] = ")";
// GLOBAL: IMPERIALISM 0x0069806c
char g_szUiOpenParen_0069806C[] = "(";
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

// --- UMapper coastline/region overlay tables (plain globals; addresses 0x006a3478 /
// 0x006a3900 are untracked scratch tables). The per-tile-edge Seapoint quads are matched
// into region-border SeaSegments that MergeSmallCityRegionsAndCompactIds consumes. ---
SeapointStretch g_seapointQuadTable_006a3478;
// GLOBAL: IMPERIALISM 0x006a3498
int g_cityRegionIdRemapTable_006a3498[0x100];
SeaSegmentStretch g_regionBorderLinkTable_006a3900;

// Per tech-item slot, the purchase cost applied/refunded against a nation's field-0x10
// metric by TTechMgr::ApplyTechItemPurchaseCostAndState (0x5b0b30) /
// RefundTechItemPurchaseCostAndClearState (0x5b0bb0). Locked/unused slots are -1.
const int g_anTechItemPurchaseCostBySlot_0066aae8[34] = {
    0,     0,      1000,   1000,   1500,   1500,  1500,  1500,  3000,  3000,  3000,  6000,
    7000,  10000,  12000,  12000,  12000,  12000, 12000, 25000, 20000, 40000, 40000, 40000,
    40000, 100000, 120000, 150000, 150000, 0,     -1,    -1,    -1,    0};

// Hex-neighbour offset tables (direction 0..5) for the 108-wide offset-coordinate grid.
const int g_hexColOffsetEvenRow_00697450[6] = {0, 1, 0, -1, -1, -1};
const int g_hexRowOffset_00697468[6] = {-1, 0, 1, 1, 0, -1};
const int g_hexColOffsetOddRow_00697480[6] = {1, 1, 1, 0, -1, 0};

// GLOBAL: IMPERIALISM 0x00697498
const int g_coarseHexColOffsetEvenRow_00697498[6] = {1, 1, 1, 0, -1, 0};
// GLOBAL: IMPERIALISM 0x006974b0
const int g_coarseHexRowOffset_006974b0[6] = {-1, 0, 1, 1, 0, -1};
// GLOBAL: IMPERIALISM 0x006974c8
const int g_coarseHexColOffsetOddRow_006974c8[6] = {0, 1, 0, -1, -1, -1};

// GLOBAL: IMPERIALISM 0x00697568
const int g_riverConnectionTypeByDirectionPair_00697568[6][6] = {
    {0, 0, 1, 2, 3, 0}, {0, 0, 0, 4, 5, 6}, {1, 0, 0, 0, 7, 8},
    {2, 4, 0, 0, 0, 9}, {3, 5, 7, 0, 0, 0}, {0, 6, 8, 9, 0, 0}};

// GLOBAL: IMPERIALISM 0x00696e40
const unsigned short g_hexDirectionBitMasks_00696e40[6] = {1, 2, 4, 8, 16, 32};

// GLOBAL: IMPERIALISM 0x00696ea8
const unsigned short g_hexDirectionBitMasksAlt_00696ea8[7] = {1, 2, 4, 8, 16, 32, 0};

// Map-generation PRNG state + region-seed grid dimensions, runtime-initialized to 0.
// GLOBAL: IMPERIALISM 0x006a38e8
unsigned int g_mapGenLcgState_006a38e8 = 0;
// GLOBAL: IMPERIALISM 0x006a38ec
int g_regionSeedGridRows_006a38ec = 0;
// GLOBAL: IMPERIALISM 0x006a38f0
int g_regionSeedGridCols_006a38f0 = 0;
// Per-mille terrain-class tile quotas seeded/scaled by the map-tuning-string parser
// (TMapMaker 0x525a30): defaults {desert 200, mountain 150, hills 250, forest 250,
// swamp 150} sum to the 1000 budget. Tuning letters map upper=more/lower=less:
// 'D'/'d' desert 300/100, 'M'/'m' mountain 300/100, 'H'/'h' hills 500/100,
// 'F'/'f' forest 500/100, 'S'/'s' swamp 300/100, 'P'/'p' total budget 750/1500,
// 'R'/'r' rivers 20/5, 'C'/'c' region seed grid 10x6 / 18x10 (fewer/more regions);
// the parser rescales the five quotas to the chosen budget. Class binding inferred
// from the tuning letters; hedged until the 0x526c20 generation pass is ported.
// GLOBAL: IMPERIALISM 0x006a38bc
int g_mapGenDesertQuota_006a38bc = 0;
// GLOBAL: IMPERIALISM 0x006a3470
int g_mapGenMountainQuota_006a3470 = 0;
// GLOBAL: IMPERIALISM 0x006a38c0
int g_mapGenHillsQuota_006a38c0 = 0;
// GLOBAL: IMPERIALISM 0x006a38f8
int g_mapGenForestQuota_006a38f8 = 0;
// GLOBAL: IMPERIALISM 0x006a38e0
int g_mapGenSwampQuota_006a38e0 = 0;
// Map-gen feature count set alongside the quotas (default 10; tuning 'm' = 20, 'p' = 5).
// GLOBAL: IMPERIALISM 0x006a38e4
int g_mapGenRiverCount_006a38e4 = 0;

// One-shot assert-suppression flags for the UMapper overlay passes (0x006a3910/0x006a3914).
int DAT_006a3910 = 0;
int DAT_006a3914 = 0;

// Private retail assert guards read by TStream's two diagnostic virtuals. No writer is
// present in the executable; a zero value takes the McAppStream.cpp assert path.
// GLOBAL: IMPERIALISM 0x006a1a10
int g_streamLine304AssertGuard = 0;
// GLOBAL: IMPERIALISM 0x006a1a14
int g_streamLine596AssertGuard = 0;

// Zone status-code PRNG seed (0x006a5aec) + display-name cache key (0x006984b8);
// see global_data_tables.h. Runtime-initialized.
// GLOBAL: IMPERIALISM 0x006a5aec
unsigned int g_zoneStatusCodePrngSeed_006a5aec = 0;
// GLOBAL: IMPERIALISM 0x006a5af0
extern "C" short g_anProvinceNameOrdinalByNationSlot_006a5af0[23] = {0};
// GLOBAL: IMPERIALISM 0x006984b8 (static init -1 in the original .data section)
int g_mapActionContextDisplayNameCacheId_006984b8 = -1;
// GLOBAL: IMPERIALISM 0x006984bc (static init 7 in the original .data section)
int g_mapActionContextDisplayNameCacheStep_006984bc = 7;

// === Map-context flavor-text string pool (procedural syllable/grammar .rdata literals
// referenced by the BuildMapContextStatusString / GenerateMappedFlavorText family).
// Empty content: reccmp pairs by the // GLOBAL address marker, not by value. ===
// GLOBAL: IMPERIALISM 0x00695794
char s_szSpaceSeparator_00695794[] = " ";
// Retail garrison-close easter-egg names. The three-byte gap after "Frog" is alignment
// padding before the adjacent "Snidely" string.
// GLOBAL: IMPERIALISM 0x00695844
extern const char g_szGarrisonSecretNationNameFrog[] = "Frog";
// GLOBAL: IMPERIALISM 0x0069584c
extern const char g_szGarrisonSecretUnitNameSnidely[] = "Snidely";
// Newline separator used by TNavyMgr's map-order interaction report builder. The
// original symbol's eight-byte comparison extent includes two alignment NULs and the
// first four bytes of the adjacent pooled "TBattleUnits" class-name literal.
// GLOBAL: IMPERIALISM 0x00695880
extern "C" const char s_szLineBreak_00695880[8] = {'\n', 0, 0, 0, 'T', 'B', 'a', 't'};
// Separator used by TViewMgr::ShowUnitHistory to build "Turn N: count message".
// The original symbol's eight-byte comparison extent includes the aligned NUL and
// the first four bytes of the adjacent pooled "Losses\n" literal.
// GLOBAL: IMPERIALISM 0x00699320
char s_szTurnHistorySeparator_00699320[8] = {':', ' ', 0, 0, 'L', 'o', 's', 's'};
// GLOBAL: IMPERIALISM 0x00699324
char s_szCombatLossesHeading_00699324[] = "Losses\n";
// GLOBAL: IMPERIALISM 0x006993e8
unsigned char g_applyMiniMapVerticalClipOffset_006993e8 = 1;
// GLOBAL: IMPERIALISM 0x0069b71c
char s_szTurnHistoryPrefix_0069b71c[] = "Turn ";
// "Adm. " prefix for the assigned-admiral name line (TShipView::Draw,
// 0x5654e0).
// GLOBAL: IMPERIALISM 0x0069578c
char s_szAdmiralPrefix_0069578c[] = "Adm. ";
// "<label>:" separator between the council-panel's nation-name/label column and its
// value column (TCouncilPanelView::Draw, 0x4fb030).
// GLOBAL: IMPERIALISM 0x00696b10
char s_szColonSeparator_00696b10[] = ":";
// GLOBAL: IMPERIALISM 0x00696674
char s_mcflavor_00696674[] = "";
// GLOBAL: IMPERIALISM 0x00696d10
char s_mcflavor_00696d10[] = "";
// GLOBAL: IMPERIALISM 0x00697238
char s_mcflavor_00697238[] = "";
// Script-dump format strings for TMapMgr::DumpAndResetMapScriptState (0x519140).
// GLOBAL: IMPERIALISM 0x006972f8
char g_szScriptFileName_006972f8[] = "script";
// GLOBAL: IMPERIALISM 0x006972e8
char g_szFmtZone_006972e8[] = "zone %d %s\n";
// GLOBAL: IMPERIALISM 0x006972d0
char g_szFmtShip_006972d0[] = "ship %d %d %d %d\n";
// GLOBAL: IMPERIALISM 0x006972bc
char g_szFmtArmy_006972bc[] = "army %d %d %d\n";
// GLOBAL: IMPERIALISM 0x006972ac
char g_szFmtCivi_006972ac[] = "civi %d %d\n";
// GLOBAL: IMPERIALISM 0x006972a0
char g_szFmtPort_006972a0[12] = "port %d\n";
// GLOBAL: IMPERIALISM 0x00697294
char g_szFmtRail_00697294[12] = "rail %d\n";
// GLOBAL: IMPERIALISM 0x00697280
char g_szFmtCapa_00697280[] = "capa %d %d %d\n";
// GLOBAL: IMPERIALISM 0x00697268
char g_szFmtLabo_00697268[] = "labo %d %d %d %d\n";
// GLOBAL: IMPERIALISM 0x00697254
char g_szFmtEmba_00697254[] = "emba %d %d %d\n";
// GLOBAL: IMPERIALISM 0x00697248
char g_szFmtYear_00697248[12] = "year %d\n";
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
char s_Data_scores_dat_0069b7fc[] = "Data/scores.dat"; // forward slash in the original binary

// Screen-offset scale (-0.3125 = -5/16) applied to a tile's isometric screen offset when
// positioning the hex-neighbor highlight polygon (BuildHexNeighborHighlightPolygonForTile
// 0x508f30).
// GLOBAL: IMPERIALISM 0x00658640
extern const float g_HexHighlightScreenScale_00658640 = -0.3125f;

// GLOBAL: IMPERIALISM 0x006a4084
short g_creditsPlaybackActive_006a4084 = 0;

// GLOBAL: IMPERIALISM 0x00668568
// Indexed directly by raw commandId (a large turn-event/menu command code, not a small
// enum) plus perTechUnlockFlag180[kProductionOrderTechId]*0x11; the real table base sits at a
// negative
// C-array-index offset baked into the instruction displacement, so only the leading
// zero run at this exact address is meaningfully checked.
short g_offerDeskSelectionIndexTable_00668568[8] = {0};
// GLOBAL: IMPERIALISM 0x006a2fe0
int g_diplomacyWarOfferSheetPosition_006a2fe0[2] = {0};
// GLOBAL: IMPERIALISM 0x006a3020
int g_diplomacyPopupLayoutPosition_006a3020[2] = {0};

// GLOBAL: IMPERIALISM 0x006a2410
int g_InfoBarDummyOrigin_006A2410[2] = {0};

// Per-strength-tier probability-split table for TArmyMgr::GenerateSpyReport's
// per-garrisoned-unit resource roll: each 3-short half sums to 100. The first half picks a
// 0-2 "point cost" for the unit; the second result is biased by 3, with selector 4 choosing
// a fixed "misc" bucket, selector 5 choosing a uniform random bucket, and every other
// selector choosing the unit's own movement class. Indexed by
// the function's winning strength tier (unclamped, matching the original -- tiers beyond
// row 5 read past this table in the original too). table[tier]+3 is the second half (at
// original address 0x0064c5de, 6 bytes/3 shorts into this same row-major table).
// GLOBAL: IMPERIALISM 0x0064c5d8
short g_MapOrderResourceRollWeightTable_0064c5d8[6][6] = {
    {50, 20, 30, 40, 30, 30}, {50, 20, 30, 50, 30, 20}, {40, 35, 25, 55, 30, 15},
    {30, 50, 20, 65, 20, 15}, {20, 65, 15, 70, 20, 10}, {10, 80, 10, 80, 10, 10},
};

// GLOBAL: IMPERIALISM 0x00696400
short g_cityProductionReserveByPolicyBand_00696400[4] = {0, 2, 6, 12};

// GLOBAL: IMPERIALISM 0x00696408
short g_aInteriorMinisterNeedPriorityOrder_00696408[10] = {17, 18, 20, 19, 2, 3, 4, 0, 1, 5};

// GLOBAL: IMPERIALISM 0x00696450
float g_cityProductionUpgradeRatioThreshold_00696450[4] = {2.0f, 2.0f, 2.0f, 0.0f};

// Groups city-action capability slots into their upgrade-compatible families.
// GLOBAL: IMPERIALISM 0x00650670
short g_cityActionCapabilityGroupBySlot_00650670[32] = {
    0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 1, 3, 2, 2, 4, 4, 4, 4, 4, 4, 0, 0};

// GLOBAL: IMPERIALISM 0x0064fab0
short g_cityBuildingSoundCueOffsets[16] = {2, 3, 4, 5, 0, 1, 6, 10, 11, 12, 13, 7, 8, 9, 14, 35};

// GLOBAL: IMPERIALISM 0x00696178
short g_cityBuildingHitTestOrder[16] = {12, 13, 7, 10, 14, 15, 9, 6, 11, 2, 3, 8, 0, 1, 4, 5};

// Threshold/sentinel table used by diplomacy trade controls: 300 selects action 11,
// values below 96 select action 9, and the remaining values select action 10.
// GLOBAL: IMPERIALISM 0x00696950
short g_awDiplomacyTradePolicyIconValueTable[7] = {95, 90, 75, 50, 25, 0, 300};

// GLOBAL: IMPERIALISM 0x00669f10
double g_dNavyDamageSplitRatioA_00669f10 = 0.25;
// GLOBAL: IMPERIALISM 0x00669f18
double g_dNavyDamageSplitRatioB_00669f18 = 0.75;

// GLOBAL: IMPERIALISM 0x00669ef8
double g_dNavyHitChanceRangeScale_00669ef8 = 0.5;
// GLOBAL: IMPERIALISM 0x00669f00
float g_fNavyHitChanceCubeOffset_00669f00 = -1.0f;
// GLOBAL: IMPERIALISM 0x00669f04
float g_fNavyHitChanceNumerator_00669f04 = 80.0f;
