#include "game/ui_core/TViewMgr.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/ui_core/TEventHandler.h"

#include "game/trade_ui/TDealBookPicture.h"
#include "game/gfx/TResourceMgr.h"

#include "game/unreachable_turn_event_dialog.h"

#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/ui_widgets/TArmyInfoView.h"
#include "game/city_ui/TEngineerDialog.h"
#include "game/ui_widgets/TCivReport.h"
#include "game/ui_widgets/TCombatReportView.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TSoundPlayer.h" // g_pSfxPlaybackSystem
#include "game/ui_core/TMacViewMgr.h"     // g_pMacViewMgr
#include "game/ui_core/TIncludeView.h"    // turn-event UI entry packet ('Incl')
#include "game/ui_core/CWMgrIterator.h"   // window-registry traversal for the full (code-0) refresh
#include "game/ui_core/quickdraw_rendering.h" // SetQuickDrawFillColor / SetQuickDrawStrokeColor
#include "game/ui_widgets/TToolBarCluster.h" // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/ui_widgets/TWorldView.h"
#include "game/assets/TMovieView.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/city_ui/TCountry.h" // FormatOverlayTerrainLabelText (terrain overlay case)
#include "game/nation/TGreatPower.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/military/TGarrisonView.h"
#include "game/map/TMapMgr.h"
#include "game/gfx/TDisplayMgr.h" // g_pDisplayMgr, g_szUiNilPointerMessage, g_szUiFailureMessage
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/app/TCouncilTickerAnimation.h"
#include "game/diplomacy_ui/TCouncilView.h"
#include "game/gfx/CTemporaryRegion.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/turn_flow_cooldown.h" // IsTurnFlowCooldownActiveAndResetExpiredState
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/ui_message_pump.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TCluster.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_core/TModalMessageCommand.h"
#include "game/ui_core/TApplication.h"
#include "game/military_ui/TSuperCivRoster.h"
#include "game/military_ui/TSuperArmyRoster.h"
#include "game/navy_ui/TSuperNavyRoster.h"
#include "game/navy_ui/TNavyRoster.h"
#include "game/navy/TTaskForce.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif
#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_screens/TScrollView.h" // nation-info modal overflow scroll wrapper
#include "game/ui_core/TStaticText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/app/TTechStorePage.h"
#include "game/military/mapped_flavor_text.h" // BuildUiMessageTextFromBracketTemplate / scanBracketExpressions
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TRadioText.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/city_ui/TCivMgr.h"
#include "game/city_ui/TPlaceCityDialog.h"
#include "game/military/TCivUnit.h"
#include "game/city/TCity.h"
#include "game/map_ui/TCitySiteView.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_text_label_helpers_decls.h"

#include <new>

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pSimMgr / turn-state
// manager). Included via global_data_tables.h.

// The display/GWorld manager (g_pDisplayMgr @ 0x6a2158); its activeDialog (+0x04) field
// holds the active main TView used as the dispatch root for turn-event UI refreshes.

#include "game/ui_core/CIncludeView.h"
#include "game/GameAssert.h"

// FUNCTION: IMPERIALISM 0x005dbe50
void BuildTurnStateStyledTextAndDispatchMainRoutine() {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CString text;

  TView* mainControl = activeDialog->ResolveControlByTag(kControlTagMain); // 'main'
  mainControl->AssertValid();

  TStaticText* labelControl = static_cast<TStaticText*>(
      activeDialog->ResolveControlByTag(IMPERIALISM_FOURCC('l', 'a', 'b', 'l')));
  if (labelControl == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UViewMgr.cpp", 0xeb3);
  }
  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b6b);
  labelControl->InstallTextStyle(style, 0);
  labelControl->SetJustification(1, false);
  g_pSimMgr->GetString(0x2737, 2, &text);
  labelControl->SetTextAndMaybeRefresh(&text, false);
  g_pSimMgr->GetString(0x2737, 2, &text);
  SetControlHoverHelpText(text, mainControl);

  TView* hostControl = activeDialog->ResolveControlByTag(IMPERIALISM_FOURCC('h', 'o', 's', 't'));
  hostControl->AssertValid();
  g_pSimMgr->GetString(0x2737, 5, &text);
  SetControlHoverHelpText(text, hostControl);

  TView* hostControl2 = activeDialog->ResolveControlByTag(IMPERIALISM_FOURCC('h', 'o', 's', 't'));
  g_pSimMgr->GetString(0x2737, 5, &text);
  SetControlHoverHelpText(text, hostControl2);

  TView* joinControl = activeDialog->ResolveControlByTag(IMPERIALISM_FOURCC('j', 'o', 'i', 'n'));
  g_pSimMgr->GetString(0x2737, 6, &text);
  SetControlHoverHelpText(text, joinControl);

  TView* nadaControl = activeDialog->ResolveControlByTag(kControlTagNada); // 'nada'
  text = CString("These books are for show");
  SetControlHoverHelpText(text, nadaControl);
}

// FUNCTION: IMPERIALISM 0x005dcdf0
bool TViewMgr::ShowNewCityDialog(TTown* town) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNewCityDialog));
  if (node == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0xbe);
  }
  // MapView.rsrc view 953's 'DLOG' pict is a TPlaceCityDialog (Mac resource oracle).
  TPlaceCityDialog* placeCity =
      static_cast<TPlaceCityDialog*>(node->ResolveControlByTag(kControlTagDialog));
  if (placeCity == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0xc0);
  }
  placeCity->StuffValues(town);
  node->Center(true, true, true);
  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  int result = node->PoseModally();
  node->Close();
  node->Free();
  return result == static_cast<int>(kControlTagCncl) ? static_cast<char>(0) : static_cast<char>(1);
}

// FUNCTION: IMPERIALISM 0x005dcf20
void TViewMgr::ShowCombatReportDialog(TCombatReportContext* reportContext) {
  TWorldView* activeMapDialog = static_cast<TWorldView*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagDialog)));
  if (activeMapDialog == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0xe2);
  }
  activeMapDialog->CenterOn(reportContext->mapTileIndex);

  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventCombatReport));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0xe5);
  }
  // MapView.rsrc view 1350's 'DLOG' pict is a TCombatReportView (Mac resource oracle).
  TCombatReportView* report = static_cast<TCombatReportView*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog)));
  if (report == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0xe6);
  }
  report->StuffValues(reportContext);

  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd0a0
int TViewMgr::ShowConstructionOptionsDialog(int dialogValue) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventEngineerBuildMenu));
  if (node == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x100);
  }
  TEngineerDialog* engineerDialog =
      static_cast<TEngineerDialog*>(node->ResolveControlByTag(kControlTagDialog));
  engineerDialog->StuffValues(static_cast<short>(dialogValue));
  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  int result = node->PoseModally();
  node->Close();
  node->Free();
  return result;
}

// FUNCTION: IMPERIALISM 0x005dd180
void TViewMgr::HandleGlobalMapNationContextSelection(int nationSlot, int unused) {
  if (static_cast<short>(nationSlot) == g_pGlobalMapState->pendingRiverMouthTile) {
    TWindow* node = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTerrainInfo));
    if (node == 0) {
      FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x11e);
    }
    node->PoseModally();
    node->Close();
    node->Free();
    return;
  }
  g_pHelpMgr->EnsureMapActionContextViewAndBuildDefaultTileMenu(nationSlot);
}

// FUNCTION: IMPERIALISM 0x005dd220
void TViewMgr::ShowTownNameDialog(int stringCode) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTownNamesStringList));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x14a);
  }
  TControl* gold = static_cast<TControl*>(node->ResolveControlByTag(kControlTagDialog)); // 'DLOG'
  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->PoseModally();
  TDeluxeText* nameText =
      static_cast<TDeluxeText*>(static_cast<TView*>(gold->ResolveControlByTag(kControlTagName)));
  if (nameText == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x156);
  }
  nameText->LoadTextResource(static_cast<short>(stringCode));
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd340
TNavyRoster* TViewMgr::MakeNavyRosterDialog(TTaskForce* activeMapOrderEntry) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNavyRoster));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x167);
  }
  TNavyRoster* page =
      static_cast<TNavyRoster*>(node->ResolveControlByTag(kControlTagPage)); // 'page'
  if (page == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x169);
  }
  page->StuffValues(activeMapOrderEntry);

  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->PoseModally();
  node->Close();
  node->Free();
  return page;
}

// FUNCTION: IMPERIALISM 0x005dd450
void TViewMgr::ShowNavyRosterDialogAndApplySelection() {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNavyRoster));
  if (node == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x183);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(kControlTagPage)); // 'page'
  if (page == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x187);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperNavyRoster* roster = ::new TSuperNavyRoster();
  int rosterOffset[2] = {0x1ca, 0x136};
  int rosterSize[2] = {0xd, 0x2e};
  roster->PopulateNavyOrderPageEntriesByMapContext(pageOwner, rosterOffset, rosterSize);
  roster->controlTag = kControlTagPage; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->IStaticText(static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746,
                         0xc);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  node->PoseModally();
  TZone* selectedZone = roster->selectedZone;
  TTaskForce* selectedTaskForce = roster->selectedTaskForce;
  node->Close();
  node->Free();

  if (selectedTaskForce != 0) {
    if (static_cast<short>(selectedTaskForce->shipOrders) == 0) {
      mapUberPicture->SetActiveMapOrderEntry(selectedTaskForce->location);
    } else {
      mapUberPicture->RefreshMapOrderEntryPanel(0);
      mapUberPicture->SetMapInteractionMode(3);
      mapUberPicture->NoticeTile(selectedTaskForce->ingotTileIndex);
    }
  } else if (selectedZone != 0) {
    mapUberPicture->SetActiveMapOrderEntry(selectedZone);
  }
}

// FUNCTION: IMPERIALISM 0x005dd770
void TViewMgr::ShowUnreachableCityDialog(void* selection) {
  turn_event_dialog::TurnEventMapSelection* mapSelection =
      static_cast<turn_event_dialog::TurnEventMapSelection*>(selection);

  TWorldView* activeMapDialog =
      static_cast<TWorldView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagDialog));
  if (activeMapDialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x1c5);
  }
  short cityRecordIndex = mapSelection->cityRecordIndex;
  activeMapDialog->CenterOn(g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex);

  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTacticalMapPictureBase));
  if (node == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x1c9);
  }
  turn_event_dialog::UnreachableTacticalMapPictureControl* gold =
      static_cast<turn_event_dialog::UnreachableTacticalMapPictureControl*>(
          node->ResolveControlByTag(kControlTagDialog));
  if (gold == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x1ca);
  }
  gold->ApplySelection(mapSelection);
  CPoint placement;
  GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd900
void TViewMgr::MakeGarrisonWindow(int tileIndex) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x1e2);
  }
  TView* page = node->ResolveControlByTag(kControlTagPage); // 'page'
  if (page == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x1e3);
  }
  static_cast<TGarrisonView*>(page)->StuffValues(static_cast<short>(tileIndex));

  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  node->PoseModally();
  node->Close();
  node->Free();

  TMapUberPicture* mapView = mapUberPicture;
  static_cast<TArmyToolbar*>(mapView->categoryPages[mapView->activeUnitCategoryIndex])
      ->SetProvince(static_cast<short>(tileIndex));
}

// FUNCTION: IMPERIALISM 0x005dda30
void TViewMgr::ShowArmyRosterDialogAndActivateProvinceSelection() {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x202);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(kControlTagPage)); // 'page'
  if (page == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x203);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperArmyRoster* roster = ::new TSuperArmyRoster();
  int rosterOffset[2] = {0x1ca, 0x136};
  int rosterSize[2] = {0xd, 0x2e};
  roster->PopulateArmyOrderPageEntries(pageOwner, rosterOffset, rosterSize);
  roster->controlTag = kControlTagPage; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->IStaticText(static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746,
                         0xb);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  node->PoseModally();
  short selectedIndex = roster->selectedCityRecordIndex;
  node->Close();
  node->Free();

  if (selectedIndex != -1) {
    mapUberPicture->SetMapInteractionMode(1);
    g_pMapContextActionManager->SetSelectedProvince(selectedIndex);
    mapUberPicture->NoticeTile(g_pGlobalMapState->cityScoreTable[selectedIndex].cityTileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005ddd20
void TViewMgr::ShowCivilianLedgerDialogAndSelectUnit() {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x232);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(kControlTagPage)); // 'page'
  if (page == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x233);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperCivRoster* roster = ::new TSuperCivRoster();
  int rosterSize[2] = {0x1ca, 0x136};
  int rosterOffset[2] = {0xd, 0x2e};
  roster->InitializeLedgerRosterPages(pageOwner, rosterOffset, rosterSize);
  roster->controlTag = kControlTagPage; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->IStaticText(static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746,
                         0xa);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->SetModality(true);
  node->PoseModally();
  short selectedIndex = roster->selectedTileIndex;
  node->Close();
  node->Free();

  if (selectedIndex != -1) {
    this->mapUberPicture->NoticeTile(selectedIndex);
    UnitOrder orderState =
        g_pGlobalMapState->terrainStateTable[selectedIndex].firstCivilianOrder->unitOrder;
    if (orderState == kUnitOrderIdle || orderState == static_cast<UnitOrder>(3) ||
        orderState == static_cast<UnitOrder>(2)) {
      g_pSelectedCivilianOrderState->HandleCivilianTileSelectionOrReportClick(selectedIndex, 2);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005de010
int TViewMgr::MakePlanetSeedDialog(const char* instruction, CString& planetSeed,
                                   const char* firstChoice, const char* secondChoice,
                                   int initialChoice, bool showCancel) const {
  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventPlanetSeedDialog));
  if (dialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x26a);
  }

  dialog->SetModality(true);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay;
  }

  TStaticText* instructionText =
      static_cast<TStaticText*>(dialog->ResolveControlByTag(kControlTagInst));
  instructionText->AssertValid();
  TextStyle instructionStyle;
  instructionStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&instructionStyle, 0, 0xe, 0);
  instructionText->InstallTextStyle(instructionStyle, 0);
  CString instructionString(instruction);
  instructionText->SetTextAndMaybeRefresh(&instructionString, false);

  TEditText* planetEdit = static_cast<TEditText*>(dialog->ResolveControlByTag(kControlTagPlan));
  planetEdit->AssertValid();
  CString editText(planetSeed);
  TextStyle editStyle;
  editStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&editStyle, 0, 0xc, 0);
  planetEdit->InstallTextStyle(editStyle, 0);
  planetEdit->InitDialogWindowAndSyncTitleIfChanged(&editText, 0);
  planetEdit->BecomeTarget();
  planetEdit->SetSelection(0, static_cast<short>(editText.GetLength()), 1);
  dialog->SetWindowTarget(planetEdit);

  COLORREF mappedThemeValue = 0;
  ResolveUiThemeColor(0x2b6c, &mappedThemeValue);
  RGBQUAD mappedTheme;
  mappedTheme.rgbBlue = static_cast<BYTE>(mappedThemeValue);
  mappedTheme.rgbGreen = static_cast<BYTE>(mappedThemeValue >> 8);
  mappedTheme.rgbRed = static_cast<BYTE>(mappedThemeValue >> 16);
  mappedTheme.rgbReserved = static_cast<BYTE>(mappedThemeValue >> 24);
  g_pDisplayMgr->SetHiliteColor(&mappedTheme);
  UpdatePaletteIndexWithDefaultFallback(0x3b);

  TRadioTextCluster* choiceCluster =
      static_cast<TRadioTextCluster*>(dialog->ResolveControlByTag(kControlTag1or2));
  choiceCluster->AssertValid();
  if (firstChoice != 0) {
    choiceCluster->Show(1, 0);
    choiceCluster->frameThemeCode = 0x2b6b;
    choiceCluster->itemInset = 2;

    TRadioText* first =
        static_cast<TRadioText*>(choiceCluster->ResolveControlByTag(kControlTagOne1));
    first->AssertValid();
    CString firstText(firstChoice);
    first->SetTextAndMaybeRefresh(&firstText, false);
    ApplyUiTextStyleAndThemeFlags(first, 0, 0xc, 0x2b6b, 0x2b6c);
    first->SetJustification(1, false);

    TRadioText* second =
        static_cast<TRadioText*>(choiceCluster->ResolveControlByTag(kControlTagTwo2));
    second->AssertValid();
    CString secondText(secondChoice);
    second->SetTextAndMaybeRefresh(&secondText, false);
    ApplyUiTextStyleAndThemeFlags(second, 0, 0xc, 0x2b6b, 0x2b6c);
    second->SetJustification(1, false);

    choiceCluster->SetSelectedTextOptionByTag(
        initialChoice == 0 ? kControlTagOne1 : kControlTagTwo2, false);
  }

  if (showCancel) {
    TControl* cancel = static_cast<TControl*>(dialog->ResolveControlByTag(kControlTagCanc));
    cancel->AssertValid();
    cancel->Show(1, 0);
    cancel->ViewEnable(1, 0);
  }

  int resultTag = dialog->PoseModally();
  if (firstChoice != 0) {
    resultTag = choiceCluster->selectedTag;
  }

  planetEdit->GetCurrentText(&editText);
  planetSeed = editText;
  dialog->Close();
  dialog->Free();
  return resultTag;
}

// FUNCTION: IMPERIALISM 0x005de4f0
bool TViewMgr::ShowCivilianReportDialogAndReturnConfirm(TCivUnit* pCivilianOrderEntry) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventCivilianInfo));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x2c1);
  }
  node->SetModality(true);
  // MapView.rsrc view 3012's 'DLOG' pict is a TCivReport (Mac resource oracle).
  TCivReport* report =
      static_cast<TCivReport*>(static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog)));
  report->StuffValues(pCivilianOrderEntry);
  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  unsigned int resultTag = node->PoseModally();
  node->Close();
  node->Free();
  return resultTag == kControlTagOkay;
}

// FUNCTION: IMPERIALISM 0x005de5d0
bool TViewMgr::DispatchProvinceOrderOverlayConfirmDialog(short cityRecordIndex,
                                                         int* categoryCounts) {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventFriendlyArmyReport));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x2e1);
  }
  node->SetModality(true);
  // MapView.rsrc view 3100's 'DLOG' pict is a TArmyInfoView (Mac resource oracle).
  TArmyInfoView* report = static_cast<TArmyInfoView*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog)));
  report->StuffValues(cityRecordIndex, categoryCounts);
  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  unsigned int resultTag = node->PoseModally();
  node->Close();
  node->Free();
  return resultTag == kControlTagOkay;
}

// FUNCTION: IMPERIALISM 0x005de8f0
void TViewMgr::DispatchUiRuntimeMessage101AAndRefreshActiveView() {
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventQueryFloater));
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUViewMgrMore, 0x33f);
  }
  CPoint placement;
  this->GetTopLeftFor(node, &placement);
  node->Locate(placement, false);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005de990
char TViewMgr::ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex,
                                                    int overlayMode, int arg4) {
  CString message;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, uiStringGroup, uiStringIndex);
  return ModalMessage(message, g_ptUiPromptModalMessage, overlayMode, arg4);
}

// FUNCTION: IMPERIALISM 0x005dea60
void TViewMgr::PostModalMessage(CString* message, int payload) {
  TModalMessageCommand* command = new TModalMessageCommand();
  command->message = *message;
  command->payload = payload;
  command->ICommand(kControlTagHeyBang, g_pAmbitApplication, 0, 0, 0);
  g_pAmbitApplication->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005deb40
char TViewMgr::DispatchGameStateEventIfLocalizedPromptAccepted(int actionTag) {
  CString message;
  MultiplayerSessionRole sessionRole = g_pSimMgr->multiplayerSessionRole;
  bool isClientSession = sessionRole == kSessionRoleClient;
  if (isClientSession) {
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x31);
  } else {
    bool hosting = sessionRole == kSessionRoleHost;
    if (hosting) {
      if (actionTag == kControlTagCgam) { // 'cgam'
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x37);
      } else {
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2f);
      }
    } else if (actionTag == kControlTagNewg) { // 'newg'
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2b);
    } else if (actionTag == kControlTagQuit) { // 'quit'
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2a);
    } else if (actionTag == kControlTagLoad) { // 'load'
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x33);
    } else {
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2b);
    }
  }
  char accepted = g_pViewMgr->ModalMessage(message, g_ptUiPromptModalMessage, 0, 1);
  if (accepted != 0) {
    bool isClientSession = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
    if (isClientSession) {
      g_pGameFlowState->SendGameControl(kControlTagAbdi, g_pSimMgr->GetPlayerCountry(), -2);
    }
  }
  return accepted;
}
