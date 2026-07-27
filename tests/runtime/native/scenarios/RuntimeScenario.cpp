#include "RuntimeScenario.h"

#include "../RuntimeRun.h"
#include "RuntimeHarness.h"
#include "RuntimeContext.h"
#include "RuntimeDebuggerTrap.h"
#include "RuntimeExceptionCapture.h"
#include "RuntimeHeartbeat.h"
#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeResultWriter.h"
#include "RuntimeUiDriver.h"
#include "screens/MainMenuDriver.h"
#include "screens/RandomSetupDriver.h"

#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/CIncludeView.h"
#include "game/gfx/CDib.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/map_ui/TCitySiteView.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TGameSetupPicture.h"
#include "game/ImperialismApp.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/map/TMiniMapView.h"
#include "game/map/TMapUberPicture.h"
#include "game/map/TMapMgr.h"
#include "game/navy_ui/TOceanDialog.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/core/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_screens.h"
#include "game/ui_tags_widgets.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

namespace {

void RunWaitingForManagers();
void RunScenarioOwnedStep();
void RunWaitingForMainMenu();
void RunWaitingForRandomSetup();
void RunSettingCountryName();
void RunSelectingDifficulty();
void RunActivatingOkay();
void RunWaitingForDirectStrategicMap();
void RunWaitingForStrategicMap();
void RunVerifyingStrategicMap();
void RunWaitingForModalDismissal();
void RunPrimingMapHover();
void RunDispatchingMapHotkey();
void RunExercisingMapHover();
void RunReturningToRandomSetup();
void RunReturningToMainMenu();
void RunReenteringRandomSetup();
void RunVerifyingReturnedRandomSetup();
void RunWaitingForSecondCitySite();
void RunWaitingForSecondPromptDismissal();
void RunWaitingForCitySiteConfirmation();
void RunWaitingForCombinedMap();
void RunVerifyingCombinedMapExtents();

RuntimeRun* g_runtimeRun = 0;

RuntimeRun& Run() {
  return *g_runtimeRun;
}

// Introductory and Easy share the setup flow: native difficulty click, then no capital pick.
RuntimeScenario& ActiveScenario() {
  return *Run().Scenario();
}

int SelectedDifficultyLevel() {
  return ActiveScenario().DifficultyLevel();
}

bool SkipsCapitalSelection() {
  return SelectedDifficultyLevel() <= 1;
}

bool IsRandomGameTest() {
  return ActiveScenario().UsesRandomGameFlow();
}

// Kinds whose runs end on a live map and want the normalized simulation
// snapshot + activated-event sequence in the result.
bool RecordsGameFlow() {
  return ActiveScenario().RecordsGameFlow();
}

const char* TestName() {
  return ActiveScenario().Name();
}

const char* PhaseName() {
  return Run().PhaseName();
}

void SetStep(RuntimeStep step, const char* phaseName, const char* action) {
  Run().SetStep(step, phaseName, action);
}

bool RequiredManagersAreInitialized() {
  return g_pGlobalUiRootController != 0 && g_pSimMgr != 0 && g_pUiRuntimeContext != 0 &&
         g_pDisplayMgr != 0 && g_pUiViewManager != 0;
}

void RequestAnotherDriverTick() {
  PostThreadMessageA(GetCurrentThreadId(), WM_NULL, 0, 0);
}

void RequestGameClose() {
  if (Run().MainWindowHandle() != 0) {
    PostMessageA(Run().MainWindowHandle(), WM_CLOSE, 0, 0);
  } else {
    PostQuitMessage(0);
  }
}

void FourCcText(unsigned int tag, char text[5]) {
  text[0] = static_cast<char>(tag >> 24);
  text[1] = static_cast<char>(tag >> 16);
  text[2] = static_cast<char>(tag >> 8);
  text[3] = static_cast<char>(tag);
  text[4] = 0;
}

void Finish(const char* status, const char* failure) {
  Run().Finish();
  if (RecordsGameFlow() && lstrcmpA(status, "passed") == 0) {
    CaptureRuntimeMapState(Run());
  }
  if (!WriteRuntimeResult(Run(), ActiveScenario(), status, failure)) {
    OutputDebugStringA("Imperialism runtime test could not write its result file.\n");
  }
  if (Run().HoldRequested()) {
    return;
  }
  RequestGameClose();
}

void Fail(const char* assertionId, const char* failure) {
  Run().RecordAssertion(assertionId, failure, true);
  RuntimeExceptionCapture::Trap(Run(), ActiveScenario(), kRuntimeDebugSemanticFailure, failure, 0);
  Finish("failed", failure);
}

void Fail(const char* failure) {
  Fail(PhaseName(), failure);
}

bool CheckCondition(const char* assertionId, bool condition, const char* failure) {
  if (!condition) {
    Run().RecordAssertion(assertionId, failure, false);
  }
  return condition;
}

bool RequireCondition(const char* assertionId, bool condition, const char* failure) {
  if (condition) {
    return true;
  }
  Fail(assertionId, failure);
  return false;
}

bool FinishFailedChecks() {
  if (!Run().HasAssertionFailures()) {
    return false;
  }
  RuntimeExceptionCapture::Trap(Run(), ActiveScenario(), kRuntimeDebugSemanticFailure,
                                Run().FirstFailureJson(), 0);
  Finish("failed", Run().FirstFailureJson());
  return true;
}

bool WaitForNextTickOrTimeout(const char* failure) {
  if (Run().PhaseElapsedMs() >= Run().PhaseTimeoutMs()) {
    Fail(failure);
    return false;
  }
  RequestAnotherDriverTick();
  return true;
}

void RecordHandledModal(const char* label) {
  CString entry;
  entry.Format("\"%s\"", label);
  RuntimeJson::AppendArrayItem(Run().HandledModals(), entry);
}

void RecordUnexpectedModal(TView* modal) {
  char tag[5];
  FourCcText(static_cast<unsigned int>(modal->controlTag), tag);
  CString entry;
  entry.Format("{\"class\": \"%s\", \"tag\": \"%s\", \"phase\": \"%s\", \"t_ms\": %lu}",
               RuntimeClassName(modal), tag, PhaseName(), Run().ElapsedMs());
  RuntimeJson::AppendArrayItem(Run().UnexpectedModals(), entry);
}

void InitializeDriver(RuntimeScenario& scenario, RuntimeRun& run) {
  g_runtimeRun = &run;
  Run().StartScenario(&scenario);
  RuntimeExceptionCapture::Install(Run(), scenario);

  if (scenario.RequiresFixture()) {
    if (!Run().HasFixturePath()) {
      Finish("failed", "\"IMPERIALISM_RUNTIME_TEST_FIXTURE is not set for load_saved_game\"");
      return;
    }
  } else if (lstrcmpA(scenario.Name(), "unknown") == 0) {
    Finish("failed", "\"unknown compiled runtime test\"");
    return;
  }
  SetStep(RunWaitingForManagers, "waiting_for_managers", "wait_for_managers");
}

void RunWaitingForManagers() {
  if (!RequiredManagersAreInitialized()) {
    WaitForNextTickOrTimeout("\"manager initialization timed out\"");
    return;
  }
  if (!ActiveScenario().RequiresMainWindow()) {
    ActiveScenario().OnManagersReady();
    return;
  }
  if (GetMainViewHostFromActiveThread() == 0) {
    WaitForNextTickOrTimeout("\"main view host initialization timed out\"");
    return;
  }
  CWnd* mainWindow = AfxGetThread()->GetMainWnd();
  if (mainWindow == 0 || mainWindow->m_hWnd == 0) {
    WaitForNextTickOrTimeout("\"main window initialization timed out\"");
    return;
  }
  Run().SetMainWindowHandle(mainWindow->m_hWnd);

  ActiveScenario().OnManagersReady();
}

bool AdvanceInitialNewspaperIfNeeded();

void RunWaitingForMainMenu() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not become active\"");
    return;
  }

  srand(Run().Seed());
  // The random-map tuning string is generated by the map-context flavor LCG, whose
  // production dynamic initializer uses GetTickCount()/16. Seeding CRT rand() alone
  // never controlled it, so one runtime seed still selected different maps.
  g_zoneStatusCodePrngSeed_006a5aec = Run().Seed();
  MainMenuDriver menu(mainView);
  if (!menu.StartRandomGame()) {
    Fail("\"main-menu random-game button or native host is missing\"");
    return;
  }
  SetStep(RunWaitingForRandomSetup, "waiting_for_random_setup", "click_main_menu_rand");
  RequestAnotherDriverTick();
}

void RunWaitingForRandomSetup() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random-map setup did not become active\"");
    return;
  }

  RandomSetupDriver setup(mainView);
  Run().SetSelectedNationSlot(setup.SelectedNationSlot());
  SetStep(RunSettingCountryName, "setting_country_name", "wait_for_event_0x05dd");
  RequestAnotherDriverTick();
}

void RunSettingCountryName() {
  TView* mainView = RuntimeMainView();
  if (!RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    Fail("\"random-map setup disappeared before set_text\"");
    return;
  }
  RandomSetupDriver setup(mainView);
  if (!setup.SetCountryName("Testland")) {
    Fail("\"country-name control is missing\"");
    return;
  }
  SetStep(RunSelectingDifficulty, "selecting_difficulty", "set_text_coun");
  RequestAnotherDriverTick();
}

void RunSelectingDifficulty() {
  TView* mainView = RuntimeMainView();
  const unsigned long expectedTag = kControlTagDif0 + SelectedDifficultyLevel();
  RandomSetupDriver setup(mainView);
  if (!setup.SelectDifficulty(expectedTag, SkipsCapitalSelection())) {
    Fail("\"requested difficulty control is missing\"");
    return;
  }
  SetStep(RunActivatingOkay, "activating_okay", "select_requested_difficulty");
  RequestAnotherDriverTick();
}

void RunActivatingOkay() {
  TView* mainView = RuntimeMainView();
  RandomSetupDriver setup(mainView);
  if (!setup.Accept(SkipsCapitalSelection())) {
    Fail("\"okay control or requested input path is missing\"");
    return;
  }
  if (SkipsCapitalSelection()) {
    SetStep(RunWaitingForDirectStrategicMap, "waiting_for_direct_strategic_map", "click_okay");
  } else {
    SetStep(RunWaitingForStrategicMap, "waiting_for_strategic_map", "activate_okay");
  }
  RequestAnotherDriverTick();
}

bool NationModesMatchSelectedNation() {
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    short expected = nationSlot == Run().SelectedNationSlot() ? 1 : 2;
    if (g_pSimMgr->nationControlModes[nationSlot] != expected) {
      return false;
    }
  }
  return true;
}

bool AdvanceInitialNewspaperIfNeeded() {
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x2103) {
    return false;
  }
  TView* mainView = RuntimeMainView();
  if (!RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TNewspaperView))) {
    Fail("\"event 0x2103 did not construct the newspaper view\"");
    return true;
  }
  if (Run().NewspaperAdvanced()) {
    WaitForNextTickOrTimeout("\"newspaper end action did not advance to the combined map\"");
    return true;
  }
  if (!ActiveScenario().BeforeInitialNewspaperExit()) {
    return true;
  }
  TControl* endControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagEnd));
  if (endControl == 0 || endControl->IsActionable() == 0) {
    Fail("\"newspaper end control is missing or disabled\"");
    return true;
  }
  Run().SetNewspaperAdvanced(true);
  Run().RecordAction("activate_newspaper_end");
  endControl->HandleEvent(endControl->GetEventNumber(), endControl, 0);
  RequestAnotherDriverTick();
  return true;
}

void RunWaitingForDirectStrategicMap() {
  const int eventCode = g_pUiRuntimeContext->currentTurnEventCode;
  if (eventCode == 0x3b8) {
    Fail("\"difficulty that skips capital selection entered the city-site selector\"");
    return;
  }
  if (eventCode == 0x5e4) {
    Fail("\"single-player random game incorrectly entered multiplayer synchronization\"");
    return;
  }
  if (AdvanceInitialNewspaperIfNeeded()) {
    return;
  }
  TView* mainView = RuntimeMainView();
  if (eventCode != 0x7dd || !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    WaitForNextTickOrTimeout("\"random game did not reach the combined strategic map\"");
    return;
  }
  if (!g_ModalViewStack.IsEmpty()) {
    RecordUnexpectedModal(static_cast<TView*>(g_ModalViewStack.GetHead()));
    Fail("\"random game unexpectedly displayed a modal capital prompt\"");
    return;
  }
  if (g_pSimMgr->difficultyLevel != SelectedDifficultyLevel()) {
    Fail("\"native difficulty selection did not store the requested level\"");
    return;
  }
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    Fail("\"single-player Easy game has a multiplayer session role\"");
    return;
  }
  if (!NationModesMatchSelectedNation()) {
    Fail("\"nation control modes do not match the setup selection\"");
    return;
  }
  TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
  if (!VerifyRuntimeStrategicCoastCornerComposite(mapView->subview2A8)) {
    Fail("\"strategic coast corners do not match the adjacency-selected atlas composite\"");
    return;
  }
  const char* holdPhase = getenv("IMPERIALISM_RUNTIME_TEST_HOLD");
  if (holdPhase != 0 && lstrcmpiA(holdPhase, "strategic") == 0) {
    RedrawWindow(mapView->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    if (!CaptureRuntimePrimarySurfaceBmp(Run().ResultPath()) ||
        !CaptureRuntimeWindowBmp(Run().ResultPath(), mapView->nativeWindow50->m_hWnd,
                                 mapView->frameWidth34, mapView->frameHeight38)) {
      Fail("\"could not capture the held strategic map\"");
      return;
    }
    Finish("passed", "null");
    return;
  }
  ActiveScenario().OnMapReadyWithoutCapitalSelection();
}

void RunWaitingForStrategicMap() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    WaitForNextTickOrTimeout("\"strategic map did not become active\"");
    return;
  }
  SetStep(RunVerifyingStrategicMap, "verifying_strategic_map", "observe_event_0x03b8");
  RequestAnotherDriverTick();
}

void RunVerifyingStrategicMap() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"strategic map did not remain active\"");
    return;
  }
  if (g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site prompt did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TDialogBehavior* behavior = modal->GetDialogBehavior();
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (behavior == 0 || behavior->defaultCommandCode != kControlTagOkay || okay == 0) {
    RecordUnexpectedModal(modal);
    Fail("\"unexpected modal while entering the strategic map\"");
    return;
  }
  RecordHandledModal("city_site_prompt");
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetStep(RunWaitingForModalDismissal, "waiting_for_modal_dismissal",
          "activate_city_site_prompt_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForModalDismissal() {
  if (!g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site prompt did not dismiss\"");
    return;
  }
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"strategic map did not remain active after the city-site prompt\"");
    return;
  }
  if (!RequireCondition("strategic.map_state.present", g_pGlobalMapState != 0,
                        "\"strategic map has no global map state\"")) {
    return;
  }
  CheckCondition("strategic.active_nation.matches_setup",
                 g_pSimMgr->activeNationSlot == Run().SelectedNationSlot(),
                 "\"active nation differs from setup selection\"");
  CheckCondition("strategic.nation_modes.match_setup", NationModesMatchSelectedNation(),
                 "\"nation control modes do not match the setup selection\"");
  CheckCondition("strategic.difficulty.normal", g_pSimMgr->difficultyLevel == 2,
                 "\"difficulty level is not Normal\"");
  if (FinishFailedChecks()) {
    return;
  }
  TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
  TView* cancel = mapView->ResolveControlByTag(kControlTagCanc);
  TView* query = mapView->ResolveControlByTag(kControlTagQuer);
  if (cancel == 0 || query == 0) {
    Fail("\"city-site toolbar button controls are missing\"");
    return;
  }
  if (mapView->miniMapViewC0 == 0) {
    Fail("\"strategic map did not create its mini-map view\"");
    return;
  }
  if (!VerifyRuntimeStrategicCoastCornerComposite(mapView->subview2A8)) {
    Fail("\"strategic coast corners do not match the adjacency-selected atlas composite\"");
    return;
  }
  // Snapshot the map here rather than leaving it to Finish: this is the first
  // strategic map, and scenarios that continue past it may start a second random game
  // whose generation is not reproducible. CaptureMapStateSnapshot only records once.
  if (RecordsGameFlow()) {
    CaptureRuntimeMapState(Run());
  }
  const char* holdPhase = getenv("IMPERIALISM_RUNTIME_TEST_HOLD");
  if (holdPhase != 0 && lstrcmpiA(holdPhase, "strategic") == 0) {
    RedrawWindow(mapView->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    if (!CaptureRuntimePrimarySurfaceBmp(Run().ResultPath()) ||
        !CaptureRuntimeWindowBmp(Run().ResultPath(), mapView->nativeWindow50->m_hWnd,
                                 mapView->frameWidth34, mapView->frameHeight38)) {
      Fail("\"could not capture the held strategic map\"");
      return;
    }
    Finish("passed", "null");
    return;
  }
  SetStep(RunPrimingMapHover, "priming_map_hover", "prime_city_site_hover");
  RequestAnotherDriverTick();
}

void RunPrimingMapHover() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !RuntimeIsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"strategic map has no city-site hover view\"");
    return;
  }

  // Drive the map's semantic draw entry directly. An invalidation plus UpdateWindow is not
  // sufficient under every virtual-display host: the window manager may coalesce the paint,
  // leaving the tile cache empty while the scenario proceeds to the hover path.
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
  CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
  mapDialog->Draw(&mapBounds);
  SetGWorld(savedSurface, savedSurfaceFlags);
  CPoint point(256, 224);
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&point, 0);
  short paintedTile = static_cast<short>(mapDialog->paintedHoverTileIndex6e);
  signed char markerIndex = g_pGlobalMapState->terrainStateTable[paintedTile].markerSlotIndex10;
  if (markerIndex == -1 || mapDialog->tileMarkers7c[markerIndex].flag == 0) {
    Fail("\"primed city-site hover tile is not present in the render cache\"");
    return;
  }
  SetStep(RunDispatchingMapHotkey, "dispatching_map_hotkey", "forward_map_hotkey_x");
  RequestAnotherDriverTick();
}

void RunDispatchingMapHotkey() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapView == 0) {
    Fail("\"strategic map has no map input view\"");
    return;
  }

  TKeyCommandEvent commandEvent;
  commandEvent.commandCode = 'x';
  commandEvent.keyFlags = 0;
  commandEvent.handledMarker = 0;
  mapView->DoKeyEvent(&commandEvent);

  TMapDialog* mapDialog = mapView->subview2A8;
  if (mapDialog == 0) {
    Fail("\"strategic map has no scrollable map dialog\"");
    return;
  }

  TCitySiteView* citySiteView = static_cast<TCitySiteView*>(mapDialog);
  if (g_wMapDialogViewportTileSpan != 9) {
    Fail("\"strategic-map viewport tile span was not initialized\"");
    return;
  }
  mapDialog->SetMapDialogCellCoordinatesAndRefresh(citySiteView->minColBound368 + 1,
                                                   citySiteView->minRowBound370 + 1, 0);
  for (int scroll = 0; scroll < 0x80; ++scroll) {
    mapView->Scroll(4);
  }
  int rightEdgeViewportX = mapDialog->viewportOrigin60.x;
  if (rightEdgeViewportX != citySiteView->maxColBound36c * 0x40) {
    Fail("\"right-edge scrolling stopped before the strategic map clamp\"");
    return;
  }
  mapView->Scroll(4);
  if (mapDialog->viewportOrigin60.x != rightEdgeViewportX) {
    Fail("\"right-edge scrolling moved beyond the strategic map clamp\"");
    return;
  }
  int viewportYBeforeTopEdgeScroll = mapDialog->viewportOrigin60.y;
  mapView->Scroll(2);
  if (mapDialog->viewportOrigin60.y <= viewportYBeforeTopEdgeScroll) {
    Fail("\"top-edge scrolling moved the strategic map viewport downward\"");
    return;
  }
  short finalTile = static_cast<short>(
      g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(Run().SelectedNationSlot()));
  for (short tile = 0; tile < 0x1950; ++tile) {
    const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
    if (terrain.GetTerrainKind() == kStrategicTerrainMountain &&
        terrain.ownerNationTag04 == Run().SelectedNationSlot()) {
      finalTile = tile;
      break;
    }
  }
  citySiteView->SetMapViewTileIndex(finalTile);
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !RuntimeIsViewKindOf(RuntimeMainView(), RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"map hotkey forwarding left the strategic map\"");
    return;
  }
  SetStep(RunExercisingMapHover, "exercising_map_hover", "exercise_city_site_hover");
  RequestAnotherDriverTick();
}

void RunExercisingMapHover() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !RuntimeIsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"strategic map has no city-site hover view\"");
    return;
  }

  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
  CPoint point(0, 0);
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&point, 0);
  SetGWorld(savedSurface, savedSurfaceFlags);
  mapView->RefreshControl();
  mapView->ForceRedraw();
  TView* cancel = mapView->ResolveControlByTag(kControlTagCanc);
  if (!RuntimeUiDriver::ClickView(cancel)) {
    Fail("\"strategic-map return button or native host is missing\"");
    return;
  }
  SetStep(RunReturningToRandomSetup, "returning_to_random_setup", "click_strategic_map_canc");
  RequestAnotherDriverTick();
}

void RunReturningToRandomSetup() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random setup did not return after leaving the strategic map\"");
    return;
  }

  TView* cancel = mainView->ResolveControlByTag(kControlTagCncl);
  if (!RuntimeUiDriver::ClickView(cancel)) {
    Fail("\"returned random setup main-menu button or native host is missing\"");
    return;
  }
  SetStep(RunReturningToMainMenu, "returning_to_main_menu", "click_returned_setup_cncl");
  RequestAnotherDriverTick();
}

void RunReturningToMainMenu() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not return after leaving random setup\"");
    return;
  }

  TView* randomButton = mainView->ResolveControlByTag(kControlTagRand);
  if (!RuntimeUiDriver::ClickView(randomButton)) {
    Fail("\"returned main-menu random-game button or native host is missing\"");
    return;
  }
  SetStep(RunReenteringRandomSetup, "reentering_random_setup", "click_returned_main_menu_rand");
  RequestAnotherDriverTick();
}

void RunReenteringRandomSetup() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random setup did not reopen from the returned main menu\"");
    return;
  }

  TView* hard = mainView->ResolveControlByTag(kControlTagDif3);
  if (!RuntimeUiDriver::ClickView(hard)) {
    Fail("\"reopened random setup difficulty control or native host is missing\"");
    return;
  }
  SetStep(RunVerifyingReturnedRandomSetup, "verifying_returned_random_setup",
          "click_reopened_setup_dif3");
  RequestAnotherDriverTick();
}

void RunVerifyingReturnedRandomSetup() {
  TView* mainView = RuntimeMainView();
  TRadioTextCluster* difficulty =
      mainView != 0
          ? static_cast<TRadioTextCluster*>(mainView->ResolveControlByTag(kControlTagDiff))
          : 0;
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd || difficulty == 0 ||
      difficulty->selectedTag88 != static_cast<int>(kControlTagDif3)) {
    Fail("\"returned random setup did not accept the difficulty click\"");
    return;
  }

  TControl* okay = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagOkay));
  if (okay == 0) {
    Fail("\"reopened random setup okay control is missing\"");
    return;
  }
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetStep(RunWaitingForSecondCitySite, "waiting_for_second_city_site",
          "activate_reopened_setup_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForSecondCitySite() {
  TView* mainView = RuntimeMainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture)) ||
      g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"second city-site selector or prompt did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (okay == 0) {
    RecordUnexpectedModal(modal);
    Fail("\"second city-site prompt has no okay control\"");
    return;
  }
  RecordHandledModal("city_site_prompt");
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetStep(RunWaitingForSecondPromptDismissal, "waiting_for_second_prompt_dismissal",
          "activate_second_city_site_prompt_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForSecondPromptDismissal() {
  if (!g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"second city-site prompt did not dismiss\"");
    return;
  }

  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !RuntimeIsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"second city-site selector has no TCitySiteView\"");
    return;
  }

  short citySite = -1;
  for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    StrategicTerrainKind terrainKind = tile.GetTerrainKind();
    bool supportsCity =
        terrainKind == kStrategicTerrainPlains || terrainKind == kStrategicTerrainFarmland ||
        terrainKind == kStrategicTerrainForest || terrainKind == kStrategicTerrainDesert;
    if (supportsCity && tile.ownerNationTag04 == Run().SelectedNationSlot() &&
        tile.recruitSearchVisited0e == 0) {
      citySite = tileIndex;
      break;
    }
  }
  if (citySite == -1) {
    Fail("\"random map has no valid city-site candidate for the selected nation\"");
    return;
  }

  SetStep(RunWaitingForCitySiteConfirmation, "waiting_for_city_site_confirmation",
          "submit_valid_city_site");
  static_cast<TCitySiteView*>(mapDialog)->HandleMapClickByInteractionMode(citySite, 0);
  RequestAnotherDriverTick();
}

void RunWaitingForCitySiteConfirmation() {
  if (g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site confirmation did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TView* dialog = modal->ResolveControlByTag(kControlTagDialog);
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (dialog == 0 || okay == 0) {
    Fail("\"city-site confirmation tree is incomplete\"");
    return;
  }
  if (modal->IsActionable() == 0 || dialog->IsActionable() == 0 || okay->IsActionable() == 0 ||
      dialog->ownerContext != modal || okay->ownerContext != dialog || modal->nativeWindow50 == 0 ||
      dialog->nativeWindow50 != modal->nativeWindow50 ||
      okay->nativeWindow50 != modal->nativeWindow50) {
    Fail("\"city-site confirmation tree is not attached to its active native host\"");
    return;
  }
  Run().CapitalConfirmationUiSnapshot() = CaptureRuntimeUiSnapshot(0x3b9, modal);
  if (g_pActiveQuickDrawSurfaceContextHead != &g_defaultQuickDrawSurfaceSentinel ||
      g_pQuickDrawMemoryDc != 0) {
    Fail("\"city-site confirmation inherited the strategic map QuickDraw surface\"");
    return;
  }
  RedrawWindow(modal->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
  const char* holdPhase = getenv("IMPERIALISM_RUNTIME_TEST_HOLD");
  if (holdPhase != 0 && lstrcmpiA(holdPhase, "capital") == 0) {
    Finish("passed", "null");
    return;
  }
  RecordHandledModal("city_site_confirmation");
  SetStep(RunWaitingForCombinedMap, "waiting_for_combined_map", "accept_city_site_confirmation");
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  RequestAnotherDriverTick();
}

void RunWaitingForCombinedMap() {
  if (AdvanceInitialNewspaperIfNeeded()) {
    return;
  }
  WaitForNextTickOrTimeout("\"accepted city site did not advance to the combined map\"");
}

void RunVerifyingCombinedMapExtents() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || RuntimeIsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"combined map retained the country-bounded city-site view\"");
    return;
  }
  if (g_pActiveQuickDrawSurfaceContextHead != &g_defaultQuickDrawSurfaceSentinel ||
      g_pQuickDrawMemoryDc != 0) {
    Fail("\"combined map retained an offscreen QuickDraw surface after construction\"");
    return;
  }
  if (Run().HoldRequested()) {
    RedrawWindow(mapView->nativeWindow50->m_hWnd, NULL, NULL,
                 RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    if (!CaptureRuntimePrimarySurfaceBmp(Run().ResultPath()) ||
        !CaptureRuntimeWindowBmp(Run().ResultPath(), mapView->nativeWindow50->m_hWnd,
                                 mapView->frameWidth34, mapView->frameHeight38)) {
      Fail("\"could not capture the held combined map\"");
      return;
    }
    Finish("passed", "null");
    return;
  }
  if (!VerifyRuntimeStrategicCoastCornerComposite(mapDialog)) {
    Fail("\"strategic coast corners do not match the adjacency-selected atlas composite\"");
    return;
  }
  if (GetMcAppUiActiveFlag() == 0) {
    Fail("\"combined map left the global UI paint gate disabled\"");
    return;
  }
  if (!VerifyRuntimeMiniMapViewportFrame(mapView->miniMapViewC0)) {
    Fail("\"mini-map viewport frame did not alter the rendered thumbnail\"");
    return;
  }

  mapDialog->RefreshControl();
  mapDialog->ForceRedraw();
  CPoint firstHoverPoint(160, 160);
  CPoint secondHoverPoint(352, 288);
  TQuickDrawBlitSurface* mapCache = g_pPrimaryRenderSurfaceContext->GetBlitSurface();
  int mapCacheBytes = mapCache->stride * (mapCache->clipRect.bottom - mapCache->clipRect.top);
  unsigned char* mapCacheBeforeHover = new unsigned char[mapCacheBytes];
  memcpy(mapCacheBeforeHover, mapCache->pixelBits, mapCacheBytes);
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  short savedInteractionMode = mapView->activeUnitCategoryIndex96;
  mapView->activeUnitCategoryIndex96 = 5;
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&firstHoverPoint, 0);
  if (g_pActiveQuickDrawSurfaceContextHead != g_pPrimaryRenderSurfaceContext ||
      memcmp(mapCacheBeforeHover, mapCache->pixelBits, mapCacheBytes) != 0) {
    mapView->activeUnitCategoryIndex96 = savedInteractionMode;
    SetGWorld(savedSurface, savedSurfaceFlags);
    delete[] mapCacheBeforeHover;
    Fail("\"combined-map hover painted its transient frame into the map cache\"");
    return;
  }
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&secondHoverPoint, 0);
  mapView->activeUnitCategoryIndex96 = savedInteractionMode;
  SetGWorld(savedSurface, savedSurfaceFlags);
  bool mapCacheUnchanged = memcmp(mapCacheBeforeHover, mapCache->pixelBits, mapCacheBytes) == 0;
  delete[] mapCacheBeforeHover;
  if (!mapCacheUnchanged) {
    Fail("\"moving the combined-map cursor retained a frame in the map cache\"");
    return;
  }
  g_MapInteractionPreviewPoint_006a3370 = CPoint(0, 0);
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == 0) {
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(0x6b, 0, 0);
    mapView->Scroll(4);
    if (mapDialog->viewportOrigin60.x != 0) {
      Fail("\"combined-map right-edge scrolling did not wrap to the left edge\"");
      return;
    }
    mapView->Scroll(8);
    if (mapDialog->viewportOrigin60.x != 0x6b * 0x40) {
      Fail("\"combined-map left-edge scrolling did not wrap to the right edge\"");
      return;
    }
  } else {
    int rightColumn = 0x6e - g_wMapDialogViewportTileSpan;
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(0x7fff, 0, 0);
    if (mapDialog->viewportOrigin60.x != rightColumn * 0x40) {
      Fail("\"combined-map scrolling stopped before the full right edge\"");
      return;
    }
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(-0x7fff, 0, 0);
    if (mapDialog->viewportOrigin60.x != 0x40) {
      Fail("\"combined-map scrolling stopped before the full left edge\"");
      return;
    }
  }

  mapDialog->SetMapDialogCellCoordinatesAndRefresh(1, 0x7fff, 0);
  if (mapDialog->viewportOrigin60.y != 0x35 * 0x40) {
    Fail("\"combined-map scrolling stopped before the full bottom edge\"");
    return;
  }
  mapDialog->SetMapDialogCellCoordinatesAndRefresh(1, -0x7fff, 0);
  if (mapDialog->viewportOrigin60.y != 0) {
    Fail("\"combined-map scrolling stopped before the full top edge\"");
    return;
  }
  ActiveScenario().OnCombinedMapReady();
}

void RunScenarioOwnedStep() {
  ActiveScenario().RunScenarioStep();
}

} // namespace

void RuntimeScenario::Start(RuntimeContext& context) {
  InitializeDriver(*this, context.Run());
}

void RuntimeScenario::Tick(RuntimeContext&) {
  if (Run().IsFinished()) {
    if (Run().HoldRequested()) {
      WriteRuntimeHeartbeat(Run());
      RequestAnotherDriverTick();
    }
    return;
  }

  Run().CountTick();
  WriteRuntimeHeartbeat(Run());
  char forcedFailure[2];
  if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_FORCE_FAILURE", forcedFailure,
                              sizeof(forcedFailure)) != 0) {
    Fail("\"forced runtime debugger failure\"");
    return;
  }
  if (Run().SpinRequestedForCurrentPhase()) {
    RequestAnotherDriverTick();
    return;
  }
  if (Run().Step() == 0) {
    Fail("\"runtime-test driver entered an invalid phase\"");
    return;
  }
  Run().Step()();
}

void RuntimeScenario::Pulse(RuntimeContext&) {
  WriteRuntimeHeartbeat(Run());
}

void RuntimeScenario::ObserveBuiltUiTree(RuntimeContext&, int eventCode, TView* root) {
  if (!IsRandomGameTest()) {
    return;
  }
  if (eventCode == 0x5dd) {
    Run().RandomSetupUiSnapshot() = CaptureRuntimeUiSnapshot(eventCode, root);
  } else if (eventCode == 0x3b8 || (SkipsCapitalSelection() && eventCode == 0x7dd)) {
    // Capture only the first arrival: later 0x7dd trees (turn-advance cycles)
    // legitimately diverge from the factory expectation as the game evolves.
    if (Run().StrategicMapUiSnapshot().IsEmpty()) {
      Run().StrategicMapUiSnapshot() = CaptureRuntimeUiSnapshot(eventCode, root);
    }
  }
  ObserveScenarioUiTree(eventCode, root);
}

void RuntimeScenario::ObserveTurnEvent(RuntimeContext&, int eventCode) {
  if (RecordsGameFlow()) {
    CString event;
    event.Format("%s\"0x%04x\"", Run().ActivatedEventSequence().GetLength() == 1 ? "" : ", ",
                 static_cast<unsigned short>(eventCode));
    Run().ActivatedEventSequence() += event;
  }
  if (RecordsGameFlow() && g_pSimMgr != 0 && g_pSimMgr->multiplayerSessionRole == 0 &&
      eventCode == 0x5e4) {
    Fail("\"single-player game entered multiplayer synchronization event 0x5e4\"");
    return;
  }
  if (SkipsCapitalSelection() && eventCode == 0x3b8) {
    Fail("\"Easy difficulty entered capital-site selection event 0x3b8\"");
    return;
  }
  if (Run().Step() != RunWaitingForCitySiteConfirmation &&
      Run().Step() != RunWaitingForCombinedMap) {
    return;
  }
  if (eventCode != 0x7dd) {
    return;
  }
  SetStep(RunVerifyingCombinedMapExtents, "verifying_combined_map_extents", "observe_event_0x07dd");
  RunVerifyingCombinedMapExtents();
}

unsigned int RuntimeScenario::RandomSeed(RuntimeContext& context) {
  return context.Seed();
}

void RuntimeScenario::FailHarness(RuntimeContext&, const char* failure) {
  Fail(failure);
}

bool RuntimeScenario::RequiresMainWindow() const {
  return true;
}

bool RuntimeScenario::RequiresFixture() const {
  return false;
}

bool RuntimeScenario::UsesRandomGameFlow() const {
  return false;
}

int RuntimeScenario::DifficultyLevel() const {
  return 2;
}

bool RuntimeScenario::RecordsGameFlow() const {
  return false;
}

bool RuntimeScenario::RequiresScenarioUiSnapshot() const {
  return false;
}

bool RuntimeScenario::BeforeInitialNewspaperExit() {
  return true;
}

void RuntimeScenario::OnManagersReady() {
  StartRandomGameFlow();
}

void RuntimeScenario::OnMapReadyWithoutCapitalSelection() {
  Pass();
}

void RuntimeScenario::OnCombinedMapReady() {
  Pass();
}

void RuntimeScenario::RunScenarioStep() {
  FailScenario("\"scenario entered an unimplemented owned phase\"");
}

void RuntimeScenario::ObserveScenarioUiTree(int, TView*) {}

void RuntimeScenario::Pass() {
  Finish("passed", "null");
}

void RuntimeScenario::FailScenario(const char* failure) {
  Fail(failure);
}

bool RuntimeScenario::Require(const char* assertionId, bool condition, const char* failure) {
  return RequireCondition(assertionId, condition, failure);
}

bool RuntimeScenario::Check(const char* assertionId, bool condition, const char* failure) {
  return CheckCondition(assertionId, condition, failure);
}

bool RuntimeScenario::FinishChecks() {
  return FinishFailedChecks();
}

bool RuntimeScenario::WaitForScenarioTick(const char* failure) {
  return WaitForNextTickOrTimeout(failure);
}

void RuntimeScenario::RequestScenarioTick() {
  RequestAnotherDriverTick();
}

void RuntimeScenario::EnterScenarioStep(const char* phaseName, const char* action) {
  SetStep(RunScenarioOwnedStep, phaseName, action);
  Run().ResetHeartbeat();
  WriteRuntimeHeartbeat(Run());
}

void RuntimeScenario::RecordSerializationRoundtripReport(const CString& reportJson) {
  Run().SerializationRoundtripJson() = reportJson;
}

void RuntimeScenario::StartRandomGameFlow() {
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
  SetStep(RunWaitingForMainMenu, "waiting_for_main_menu", "post_turn_event_0x05dc");
  RequestAnotherDriverTick();
}

TView* RuntimeScenario::CurrentMainView() const {
  return RuntimeMainView();
}

unsigned long RuntimeScenario::ScenarioPhaseTicks() const {
  return Run().PhaseTicks();
}

unsigned long RuntimeScenario::ScenarioPhaseElapsedMs() const {
  return Run().PhaseElapsedMs();
}

const char* RuntimeScenario::FixturePath() const {
  return Run().FixturePath();
}

void RuntimeScenario::SetSelectedNation(short nationSlot) {
  Run().SetSelectedNationSlot(nationSlot);
}

bool RuntimeScenario::AdvanceNewspaperIfNeeded() {
  return AdvanceInitialNewspaperIfNeeded();
}

void RuntimeScenario::ResetNewspaperAdvance() {
  Run().SetNewspaperAdvanced(false);
}

void RuntimeScenario::RecordUnexpectedModalView(TView* modal) {
  RecordUnexpectedModal(modal);
}

bool RuntimeScenario::HasScenarioUiSnapshot() const {
  return !Run().ScenarioUiSnapshot().IsEmpty();
}

void RuntimeScenario::CaptureScenarioUiSnapshot(int eventCode, TView* root) {
  Run().ScenarioUiSnapshot() = CaptureRuntimeUiSnapshot(eventCode, root);
}

bool RuntimeScenario::HoldAtScenarioScreen(const char* screenName) const {
  return Run().HoldAt(screenName);
}

void RuntimeTestObserveBuiltUiTree(int eventCode, TView* root) {
  RuntimeHarness::ObserveBuiltUiTree(eventCode, root);
}
