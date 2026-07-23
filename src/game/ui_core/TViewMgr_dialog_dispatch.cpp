// TViewMgr turn-event dialog dispatch and roster/prompt dialogs. Split from
// TViewMgr.cpp along the original module seam: these 18 functions live in
// Cross/UViewMgr.more.cpp per the assert-path module map (15 samples,
// docs/reference/original_module_map.csv), the rest of TViewMgr in
// Cross/UViewMgr.cpp (bd imperialism-decomp-8mo.15).
#include "game/ui_core/TViewMgr.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/ui_core/TEventHandler.h"

#include "game/trade_ui/TDealBookPicture.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"

#include "game/turn_event_dialog_provisional.h"

#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/ui_widgets/TArmyInfoView.h"
#include "game/ui_widgets/TCivReport.h"
#include "game/ui_widgets/TCombatReportView.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TSoundPlayer.h" // g_pSfxPlaybackSystem
#include "game/ui_core/TMacViewMgr.h"     // g_pStrategicMapViewSystem
#include "game/ui_core/TIncludeView.h"    // turn-event UI entry packet ('Incl')
#include "game/ui_core/CWMgrIterator.h"   // window-registry traversal for the full (code-0) refresh
#include "game/ui_core/quickdraw_rendering.h" // SetQuickDrawFillColor / SetQuickDrawStrokeColor
#include "game/ui_widgets/TToolBarCluster.h" // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/assets/TMovieView.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/globals/prelude.h"
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
#include "game/ui_control_tags.h"
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

namespace {
using turn_event_dialog::GoldCommitControl;
using turn_event_dialog::GoldDialogControl;
} // namespace

// FUNCTION: IMPERIALISM 0x005dcdf0
char TViewMgr::ShowNewCityDialog(TTown* town) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNewCityDialog));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xbe);
  }
  // MapView.rsrc view 953's 'DLOG' pict is a TPlaceCityDialog (Mac resource oracle).
  TPlaceCityDialog* placeCity =
      static_cast<TPlaceCityDialog*>(node->ResolveControlByTag(kControlTagDialog));
  if (placeCity == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xc0);
  }
  placeCity->StuffValues(town);
  node->Center(1, 1, 1);
  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  int result = node->PoseModally();
  node->Close();
  node->Free();
  return result == static_cast<int>(kControlTagCncl) ? static_cast<char>(0) : static_cast<char>(1);
}

// FUNCTION: IMPERIALISM 0x005dcf20
void TViewMgr::ShowCombatReportDialog(TCombatReportContext* reportContext) {
  GoldCommitControl* rootGold = static_cast<GoldCommitControl*>(
      static_cast<TView*>(g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagDialog)));
  if (rootGold == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xe2);
  }
  rootGold->NotifyGoldControlOfTurnEventCode(currentTurnEventCode);

  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventCombatReport));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xe5);
  }
  // MapView.rsrc view 1350's 'DLOG' pict is a TCombatReportView (Mac resource oracle).
  TCombatReportView* report = static_cast<TCombatReportView*>(
      static_cast<TView*>(node->ResolveControlByTag(kControlTagDialog)));
  if (report == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0xe6);
  }
  report->StuffValues(reportContext);

  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd0a0
int TViewMgr::ShowConstructionOptionsDialog(int dialogValue) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventEngineerBuildMenu));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x100);
  }
  // MapView.rsrc view 7200's 'DLOG' pict is a TEngineerDialog (Mac resource oracle), and
  // slot 0x68 is its first new virtual -- but that body (0x4d0810, 3,136 bytes) is still
  // autogen-owned, so declaring the virtual here would cross the manual/autogen boundary.
  turn_event_dialog::TDialogValueControl* engineerDialog =
      static_cast<turn_event_dialog::TDialogValueControl*>(
          node->ResolveControlByTag(kControlTagDialog));
  engineerDialog->StuffValues(reinterpret_cast<void*>(dialogValue));
  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  int result = node->PoseModally();
  node->Close();
  node->Free();
  return result;
}

// FUNCTION: IMPERIALISM 0x005dd180
void TViewMgr::HandleGlobalMapNationContextSelection(int nationSlot, int unused) {
  (void)unused;
  if (static_cast<short>(nationSlot) == g_pGlobalMapState->pendingRiverMouthTile22) {
    TWindow* node = static_cast<TWindow*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTerrainInfo));
    if (node == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x11e);
    }
    node->PoseModally();
    node->Close();
    node->Free();
    return;
  }
  g_pHelpMgr->EnsureMapActionContextViewAndBuildDefaultTileMenu(nationSlot);
}

// FUNCTION: IMPERIALISM 0x005dd220
void TViewMgr::HandleTurnEventDialogFactorySlotE4(int stringCode) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventProvisional1C52));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x14a);
  }
  TControl* gold = static_cast<TControl*>(node->ResolveControlByTag(0x444c4f47)); // 'GOLD'
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->PoseModally();
  TDeluxeText* nameText =
      static_cast<TDeluxeText*>(static_cast<TView*>(gold->ResolveControlByTag(0x6e616d65)));
  if (nameText == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x156);
  }
  nameText->SetTextFromUiStringResourceId(static_cast<short>(stringCode));
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd340
TNavyRoster* TViewMgr::MakeNavyRosterDialog(TTaskForce* activeMapOrderEntry) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNavyRoster));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x167);
  }
  TNavyRoster* page = static_cast<TNavyRoster*>(node->ResolveControlByTag(0x70616765)); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x169);
  }
  page->StuffValues(activeMapOrderEntry);

  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->PoseModally();
  node->Close();
  node->Free();
  return page;
}

// Build the Mac-evidenced Navy Roster screen around a TSuperNavyRoster page. Row clicks
// return either a loose ship's zone or an existing task force; apply that choice to the
// strategic map only after the modal dialog has released its view tree.
// FUNCTION: IMPERIALISM 0x005dd450
void TViewMgr::ShowNavyRosterDialogAndApplySelection() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNavyRoster));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x183);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(0x70616765)); // 'page'
  if (page == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x187);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperNavyRoster* roster = ::new TSuperNavyRoster();
  int rosterOffset[2] = {0x1ca, 0x136};
  int rosterSize[2] = {0xd, 0x2e};
  roster->PopulateNavyOrderPageEntriesByMapContext(pageOwner, rosterOffset, rosterSize);
  roster->controlTag = 0x70616765; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->InitializeTextEntryBaseAndOptionalStringResource(
      static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746, 0xc);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  node->PoseModally();
  TZone* selectedZone = roster->selectedZone84;
  TTaskForce* selectedTaskForce = roster->selectedTaskForce88;
  node->Close();
  node->Free();

  if (selectedTaskForce != 0) {
    if (static_cast<short>(selectedTaskForce->shipOrders) == 0) {
      mapUberPictureF0->SetActiveMapOrderEntry(selectedTaskForce->location);
    } else {
      mapUberPictureF0->RefreshMapOrderEntryPanel(0);
      mapUberPictureF0->SetMapInteractionMode(3);
      mapUberPictureF0->NoticeTile(selectedTaskForce->ingotTileIndex);
    }
  } else if (selectedZone != 0) {
    mapUberPictureF0->SetActiveMapOrderEntry(selectedZone);
  }
}

// FUNCTION: IMPERIALISM 0x005dd770
void TViewMgr::HandleTurnEventDialogFactorySlotE8(void* selection) {
  // Only the +2 city-record index is established for this opaque event payload.
  struct TurnEventMapSelection {
    short unresolved0;
    short cityRecordIndex2;
  };
  TurnEventMapSelection* mapSelection = static_cast<TurnEventMapSelection*>(selection);

  GoldCommitControl* activeGold = static_cast<GoldCommitControl*>(
      g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagDialog));
  if (activeGold == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1c5);
  }
  short cityRecordIndex = mapSelection->cityRecordIndex2;
  activeGold->NotifyGoldControlOfTurnEventCode(
      g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex04);

  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventProvisional0F0A));
  if (node == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1c9);
  }
  turn_event_dialog::TDialogValueControl* gold =
      static_cast<turn_event_dialog::TDialogValueControl*>(
          node->ResolveControlByTag(kControlTagDialog));
  if (gold == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1ca);
  }
  gold->StuffValues(selection);
  POINT placement;
  ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005dd900
void TViewMgr::HandleTurnEventDialogFactorySlotEC(int mapSelection) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1e2);
  }
  TView* page = node->ResolveControlByTag(0x70616765); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x1e3);
  }
  // Mac identity plus the Windows +0x8c tile-index store recover the concrete page as
  // TGarrisonView. StuffValues rebuilds its TArmyUnitLine roster for this map tile.
  static_cast<TGarrisonView*>(page)->StuffValues(static_cast<short>(mapSelection));

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  node->PoseModally();
  node->Close();
  node->Free();

  TMapUberPicture* mapView = mapUberPictureF0;
  static_cast<TArmyToolbar*>(mapView->categoryPages[mapView->activeUnitCategoryIndex96])
      ->SetProvince(static_cast<short>(mapSelection));
}

// Replace the factory dialog's generic 'page' child with the resource-backed army roster.
// The selected roster row is a city/province record index; after the modal closes, make it
// the army manager's active province and center the strategic map on that record's tile.
// FUNCTION: IMPERIALISM 0x005dda30
void TViewMgr::ShowArmyRosterDialogAndActivateProvinceSelection() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x202);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(0x70616765)); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x203);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperArmyRoster* roster = ::new TSuperArmyRoster();
  int rosterOffset[2] = {0x1ca, 0x136};
  int rosterSize[2] = {0xd, 0x2e};
  roster->PopulateArmyOrderPageEntries(pageOwner, rosterOffset, rosterSize);
  roster->controlTag = 0x70616765; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->InitializeTextEntryBaseAndOptionalStringResource(
      static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746, 0xb);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  node->PoseModally();
  short selectedIndex = roster->selectedIndex84;
  node->Close();
  node->Free();

  if (selectedIndex != -1) {
    mapUberPictureF0->SetMapInteractionMode(1);
    g_pMapContextActionManager->SetActiveProvinceSelection(selectedIndex);
    mapUberPictureF0->NoticeTile(g_pGlobalMapState->cityScoreTable[selectedIndex].cityTileIndex04);
  }
}

// FUNCTION: IMPERIALISM 0x005ddd20
void TViewMgr::ShowCivilianLedgerDialogAndSelectUnit() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x232);
  }
  TControl* page = static_cast<TControl*>(node->ResolveControlByTag(0x70616765)); // 'page'
  if (page == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x233);
  }
  TView* pageOwner = page->ownerContext;
  page->Free();

  TSuperCivRoster* roster = ::new TSuperCivRoster();
  int rosterBounds[4] = {0x1ca, 0x136, 0xd, 0x2e};
  TView* runningDialog = roster;
  roster->InitializeLedgerRosterPages(pageOwner, rosterBounds, &runningDialog);
  roster->controlTag = 0x70616765; // 'page'

  TStaticText* textEntry = ::new TStaticText();
  int textOffset[2] = {0x4d, 0x11};
  int textSize[2] = {0x80, 0x12};
  textEntry->InitializeTextEntryBaseAndOptionalStringResource(
      static_cast<TControl*>(pageOwner), textOffset, textSize, 5, 5, 0x2746, 0xa);
  ApplyControlThemeStyleAndOptionalCaption(textEntry, 0, 0xe, 0x2b6a, -2, 0);

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->SetModality(1);
  node->PoseModally();
  short selectedIndex = roster->selectedTileIndex84;
  node->Close();
  node->Free();

  if (selectedIndex != -1) {
    this->mapUberPictureF0->NoticeTile(selectedIndex);
    UnitOrder orderState =
        g_pGlobalMapState->terrainStateTable[selectedIndex].firstCivilianOrder20->unitOrder;
    if (orderState == kUnitOrderIdle || orderState == static_cast<UnitOrder>(3) ||
        orderState == static_cast<UnitOrder>(2)) {
      g_pSelectedCivilianOrderState->HandleCivilianTileSelectionOrReportClick(selectedIndex, 2);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005de010
int TViewMgr::MakePlanetSeedDialog(const char* instruction, CString& planetSeed,
                                   const char* firstChoice, const char* secondChoice,
                                   int initialChoice, unsigned char showCancel) const {
  TWindow* dialog = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventPlanetSeedDialog));
  if (dialog == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x26a);
  }

  dialog->SetModality(1);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay;
  }

  TStaticText* instructionText =
      static_cast<TStaticText*>(dialog->ResolveControlByTag(0x696e7374 /* 'inst' */));
  instructionText->AssertValid();
  TextStyle instructionStyle;
  instructionStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&instructionStyle, 0, 0xe, 0);
  instructionText->InstallTextStyle(instructionStyle, 0);
  CString instructionString(instruction);
  instructionText->SetTextAndMaybeRefresh(&instructionString, 0);

  TEditText* planetEdit =
      static_cast<TEditText*>(dialog->ResolveControlByTag(0x706c616e /* 'plan' */));
  planetEdit->AssertValid();
  CString editText(planetSeed);
  TextStyle editStyle;
  editStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&editStyle, 0, 0xc, 0);
  planetEdit->InstallTextStyle(editStyle, 0);
  planetEdit->InitDialogWindowAndSyncTitleIfChanged(&editText, 0);
  planetEdit->BecomeTarget();
  planetEdit->SetEditSelectionAndScrollCaret(0, static_cast<short>(editText.GetLength()), 1);
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
      static_cast<TRadioTextCluster*>(dialog->ResolveControlByTag(0x316f7232 /* '1or2' */));
  choiceCluster->AssertValid();
  if (firstChoice != 0) {
    choiceCluster->SetEnabled(1, 0);
    choiceCluster->frameThemeCode90 = 0x2b6b;
    choiceCluster->itemInset92 = 2;

    TRadioText* first =
        static_cast<TRadioText*>(choiceCluster->ResolveControlByTag(0x6f6e6531 /* 'one1' */));
    first->AssertValid();
    CString firstText(firstChoice);
    first->SetTextAndMaybeRefresh(&firstText, 0);
    ApplyUiTextStyleAndThemeFlags(first, 0, 0xc, 0x2b6b, 0x2b6c);
    first->SetTextAlignmentAndMaybeRefresh(1, 0);

    TRadioText* second =
        static_cast<TRadioText*>(choiceCluster->ResolveControlByTag(0x74776f32 /* 'two2' */));
    second->AssertValid();
    CString secondText(secondChoice);
    second->SetTextAndMaybeRefresh(&secondText, 0);
    ApplyUiTextStyleAndThemeFlags(second, 0, 0xc, 0x2b6b, 0x2b6c);
    second->SetTextAlignmentAndMaybeRefresh(1, 0);

    choiceCluster->SetSelectedTextOptionByTag(
        initialChoice == 0 ? 0x6f6e6531 /* 'one1' */ : 0x74776f32 /* 'two2' */, false);
  }

  if (showCancel != 0) {
    TControl* cancel = static_cast<TControl*>(dialog->ResolveControlByTag(kControlTagCanc));
    cancel->AssertValid();
    cancel->SetEnabled(1, 0);
    cancel->SetState(1, 0);
  }

  int resultTag = dialog->PoseModally();
  if (firstChoice != 0) {
    resultTag = choiceCluster->selectedTag88;
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
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventCivilianInfo));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x2c1);
  }
  node->SetModality(1);
  // MapView.rsrc view 3012's 'DLOG' pict is a TCivReport (Mac resource oracle).
  TCivReport* report =
      static_cast<TCivReport*>(static_cast<TView*>(node->ResolveControlByTag(0x444c4f47)));
  report->PopulateCivilianReportContent(pCivilianOrderEntry);
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  unsigned int resultTag = node->PoseModally();
  node->Close();
  node->Free();
  return resultTag == 0x6f6b6179;
}

// FUNCTION: IMPERIALISM 0x005de5d0
bool TViewMgr::DispatchProvinceOrderOverlayConfirmDialog(short cityRecordIndex,
                                                         int* categoryCounts) {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventFriendlyArmyReport));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x2e1);
  }
  node->SetModality(1);
  // MapView.rsrc view 3100's 'DLOG' pict is a TArmyInfoView (Mac resource oracle).
  TArmyInfoView* report =
      static_cast<TArmyInfoView*>(static_cast<TView*>(node->ResolveControlByTag(0x444c4f47)));
  report->PopulateFriendlyArmyReportContent(cityRecordIndex, categoryCounts);
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  unsigned int resultTag = node->PoseModally();
  node->Close();
  node->Free();
  return resultTag == 0x6f6b6179;
}

// FUNCTION: IMPERIALISM 0x005de8f0
void TViewMgr::DispatchUiRuntimeMessage101AAndRefreshActiveView() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventQueryFloater));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgrMore_0069B740, 0x33f);
  }
  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  node->PoseModally();
  node->Close();
  node->Free();
}

// FUNCTION: IMPERIALISM 0x005de990
char TViewMgr::ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex,
                                                    int overlayMode, int arg4) {
  CString message;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, uiStringGroup,
                                                                  uiStringIndex);
  return ModalMessage(message, g_ptUiPromptModalMessage, overlayMode, arg4);
}

// FUNCTION: IMPERIALISM 0x005dea60
void TViewMgr::CreateModalMessageCommandAndQueue(CString* message, int payload) {
  TModalMessageCommand* command = new TModalMessageCommand();
  command->message = *message;
  command->payload = payload;
  command->InitializeRangePair(0x48657921 /* 'Hey!' */, g_pGlobalUiRootController, 0, 0, 0);
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x005deb40
char TViewMgr::DispatchGameStateEventIfLocalizedPromptAccepted(int actionTag) {
  CString message;
  int sessionRole = g_pSimMgr->multiplayerSessionRole;
  unsigned char isClientSession = sessionRole == 2;
  if (isClientSession != 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x31);
  } else {
    unsigned char hosting = sessionRole == 1;
    if (hosting != 0) {
      if (actionTag == 0x6367616d) { // 'magc'
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x37);
      } else {
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2f);
      }
    } else if (actionTag == 0x6e657767) { // 'gwen'
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2b);
    } else if (actionTag == 0x71756974) { // 'quit'
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2a);
    } else if (actionTag == 0x6c6f6164) { // 'load'
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x33);
    } else {
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2737, 0x2b);
    }
  }
  char accepted = g_pUiRuntimeContext->ModalMessage(message, g_ptUiPromptModalMessage, 0, 1);
  if (accepted != 0) {
    unsigned char isClientSession = g_pSimMgr->multiplayerSessionRole == 2;
    if (isClientSession != 0) {
      g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x61626469, // 'abdi'
                                                         g_pSimMgr->GetActiveNationId(), -2);
    }
  }
  return accepted;
}
