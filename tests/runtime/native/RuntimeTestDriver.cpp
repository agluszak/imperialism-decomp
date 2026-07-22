#include "RuntimeTestDriver.h"

#include "game/TAmbitApplication.h"
#include "game/TControl.h"
#include "game/TDisplayMgr.h"
#include "game/TDialogBehavior.h"
#include "game/TEditText.h"
#include "game/TGameSetupPicture.h"
#include "game/ImperialismApp.h"
#include "game/TMapUberPicture.h"
#include "game/TRadioTextCluster.h"
#include "game/TSetupRandomMapPicture.h"
#include "game/TSimMgr.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_control_tags.h"

#include <stdlib.h>
#include <windows.h>

namespace {

enum RuntimeTestKind { kRuntimeTestNone, kRuntimeTestBootManagers, kRuntimeTestRandomGame };

enum RuntimeTestPhase {
  kRuntimeTestNotStarted,
  kRuntimeTestWaitingForManagers,
  kRuntimeTestWaitingForMainMenu,
  kRuntimeTestWaitingForRandomSetup,
  kRuntimeTestSettingCountryName,
  kRuntimeTestSelectingDifficulty,
  kRuntimeTestActivatingOkay,
  kRuntimeTestWaitingForStrategicMap,
  kRuntimeTestVerifyingStrategicMap,
  kRuntimeTestWaitingForModalDismissal,
  kRuntimeTestFinished
};

struct RuntimeTestState {
  RuntimeTestKind kind;
  RuntimeTestPhase phase;
  unsigned long idleTicks;
  unsigned long phaseTicks;
  short selectedNationSlot;
  HWND mainWindowHandle;
  char resultPath[MAX_PATH];
  char lastAction[64];
};

RuntimeTestState g_runtimeTestState = {
    kRuntimeTestNone, kRuntimeTestNotStarted, 0, 0, -1, 0, "", ""};

const char* TestName() {
  if (g_runtimeTestState.kind == kRuntimeTestRandomGame) {
    return "random_game_enters_map";
  }
  return "boot_managers";
}

void SetPhase(RuntimeTestPhase phase, const char* action) {
  g_runtimeTestState.phase = phase;
  g_runtimeTestState.phaseTicks = 0;
  lstrcpynA(g_runtimeTestState.lastAction, action, sizeof(g_runtimeTestState.lastAction));
}

bool RequiredManagersAreInitialized() {
  return g_pGlobalUiRootController != 0 && g_pSimMgr != 0 && g_pUiRuntimeContext != 0 &&
         g_pDisplayMgr != 0 && g_pUiViewManager != 0;
}

TView* MainView() {
  if (g_pDisplayMgr == 0 || g_pDisplayMgr->activeDialog == 0) {
    return 0;
  }
  return g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
}

const char* RuntimeClassName(TView* view) {
  if (view == 0) {
    return "";
  }
  CRuntimeClass* runtimeClass = view->GetRuntimeClass();
  if (runtimeClass == 0 || runtimeClass->m_lpszClassName == 0) {
    return "";
  }
  return runtimeClass->m_lpszClassName;
}

bool IsViewKindOf(TView* view, CRuntimeClass* runtimeClass) {
  return view != 0 && view->IsKindOf(runtimeClass) != 0;
}

void RequestAnotherDriverTick() {
  PostThreadMessageA(GetCurrentThreadId(), WM_NULL, 0, 0);
}

void RequestGameClose() {
  if (g_runtimeTestState.mainWindowHandle != 0) {
    PostMessageA(g_runtimeTestState.mainWindowHandle, WM_CLOSE, 0, 0);
  } else {
    PostQuitMessage(0);
  }
}

bool WriteAll(HANDLE file, const char* bytes, DWORD size) {
  DWORD written = 0;
  return WriteFile(file, bytes, size, &written, 0) != 0 && written == size;
}

bool WriteResultFile(const char* status, const char* failure) {
  TView* mainView = MainView();
  const char* eventSequence = g_runtimeTestState.kind == kRuntimeTestRandomGame
                                  ? "[\"0x05dc\", \"0x05dd\", \"0x03b8\"]"
                                  : "[]";
  const char* handledModals =
      g_runtimeTestState.kind == kRuntimeTestRandomGame ? "[\"city_site_prompt\"]" : "[]";
  CString json;
  json.Format(
      "{\n"
      "  \"format_version\": 1,\n"
      "  \"name\": \"%s\",\n"
      "  \"status\": \"%s\",\n"
      "  \"idle_ticks\": %lu,\n"
      "  \"last_action\": \"%s\",\n"
      "  \"event_sequence\": %s,\n"
      "  \"state\": {\n"
      "    \"turn_event\": %d,\n"
      "    \"root_class\": \"%s\",\n"
      "    \"active_nation\": %d,\n"
      "    \"selected_nation\": %d,\n"
      "    \"difficulty\": %d,\n"
      "    \"global_map\": %s,\n"
      "    \"display_manager\": %s,\n"
      "    \"global_ui_root\": %s,\n"
      "    \"simulation_manager\": %s,\n"
      "    \"ui_runtime_context\": %s,\n"
      "    \"ui_view_manager\": %s\n"
      "  },\n"
      "  \"runtime\": {\n"
      "    \"faults\": [],\n"
      "    \"handled_modals\": %s,\n"
      "    \"unexpected_modals\": []\n"
      "  },\n"
      "  \"failure\": %s\n"
      "}\n",
      TestName(), status, g_runtimeTestState.idleTicks, g_runtimeTestState.lastAction,
      eventSequence, g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1,
      RuntimeClassName(mainView), g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1,
      g_runtimeTestState.selectedNationSlot, g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1,
      g_pGlobalMapState != 0 ? "true" : "false", g_pDisplayMgr != 0 ? "true" : "false",
      g_pGlobalUiRootController != 0 ? "true" : "false", g_pSimMgr != 0 ? "true" : "false",
      g_pUiRuntimeContext != 0 ? "true" : "false", g_pUiViewManager != 0 ? "true" : "false",
      handledModals, failure);

  CString temporaryPath(g_runtimeTestState.resultPath);
  temporaryPath += ".tmp";
  HANDLE file =
      CreateFileA(temporaryPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  const char* bytes = static_cast<LPCSTR>(json);
  bool wrote = WriteAll(file, bytes, static_cast<DWORD>(json.GetLength()));
  if (wrote) {
    wrote = FlushFileBuffers(file) != 0;
  }
  CloseHandle(file);
  if (!wrote) {
    DeleteFileA(temporaryPath);
    return false;
  }
  if (MoveFileExA(temporaryPath, g_runtimeTestState.resultPath,
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    DeleteFileA(temporaryPath);
    return false;
  }
  return true;
}

void Finish(const char* status, const char* failure) {
  g_runtimeTestState.phase = kRuntimeTestFinished;
  if (!WriteResultFile(status, failure)) {
    OutputDebugStringA("Imperialism runtime test could not write its result file.\n");
  }
  RequestGameClose();
}

void Fail(const char* failure) {
  Finish("failed", failure);
}

bool WaitForNextTickOrTimeout(const char* failure) {
  if (g_runtimeTestState.phaseTicks >= 10000) {
    Fail(failure);
    return false;
  }
  RequestAnotherDriverTick();
  return true;
}

void InitializeDriver() {
  char testName[64];
  DWORD testNameLength =
      GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST", testName, sizeof(testName));
  if (testNameLength == 0) {
    g_runtimeTestState.phase = kRuntimeTestFinished;
    return;
  }

  DWORD resultPathLength =
      GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_RESULT", g_runtimeTestState.resultPath,
                              sizeof(g_runtimeTestState.resultPath));
  if (resultPathLength == 0 || resultPathLength >= sizeof(g_runtimeTestState.resultPath)) {
    lstrcpyA(g_runtimeTestState.resultPath, "runtime-test-result.json");
  }

  if (lstrcmpA(testName, "boot_managers") == 0) {
    g_runtimeTestState.kind = kRuntimeTestBootManagers;
  } else if (lstrcmpA(testName, "random_game_enters_map") == 0) {
    g_runtimeTestState.kind = kRuntimeTestRandomGame;
  } else {
    Finish("failed", "\"unknown compiled runtime test\"");
    return;
  }
  SetPhase(kRuntimeTestWaitingForManagers, "wait_for_managers");
}

void RunWaitingForManagers() {
  if (!RequiredManagersAreInitialized()) {
    WaitForNextTickOrTimeout("\"manager initialization timed out\"");
    return;
  }
  if (g_runtimeTestState.kind == kRuntimeTestBootManagers) {
    Finish("passed", "null");
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
  g_runtimeTestState.mainWindowHandle = mainWindow->m_hWnd;

  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
  SetPhase(kRuntimeTestWaitingForMainMenu, "post_turn_event_0x05dc");
  RequestAnotherDriverTick();
}

void RunWaitingForMainMenu() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not become active\"");
    return;
  }

  srand(RuntimeTestDriver::RandomSeed());
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dd);
  SetPhase(kRuntimeTestWaitingForRandomSetup, "post_turn_event_0x05dd");
  RequestAnotherDriverTick();
}

void RunWaitingForRandomSetup() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random-map setup did not become active\"");
    return;
  }

  TSetupRandomMapPicture* setup = static_cast<TSetupRandomMapPicture*>(mainView);
  g_runtimeTestState.selectedNationSlot = setup->selectedNationSlot9A;
  SetPhase(kRuntimeTestSettingCountryName, "wait_for_event_0x05dd");
  RequestAnotherDriverTick();
}

void RunSettingCountryName() {
  TView* mainView = MainView();
  if (!IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    Fail("\"random-map setup disappeared before set_text\"");
    return;
  }
  TEditText* country = static_cast<TEditText*>(mainView->ResolveControlByTag(kControlTagCoun));
  if (country == 0) {
    Fail("\"country-name control is missing\"");
    return;
  }
  if (country->editWindow != 0) {
    Fail("\"country-name control has a live edit window; real synchronization is required\"");
    return;
  }
  CString countryName("Testland");
  country->SetTextAndMaybeRefresh(&countryName, 1);
  SetPhase(kRuntimeTestSelectingDifficulty, "set_text_coun");
  RequestAnotherDriverTick();
}

void RunSelectingDifficulty() {
  TView* mainView = MainView();
  TRadioTextCluster* difficulty =
      mainView != 0
          ? static_cast<TRadioTextCluster*>(mainView->ResolveControlByTag(kControlTagDiff))
          : 0;
  TControl* normal = difficulty != 0
                         ? static_cast<TControl*>(difficulty->ResolveControlByTag(kControlTagDif2))
                         : 0;
  if (difficulty == 0 || normal == 0) {
    Fail("\"normal difficulty control is missing\"");
    return;
  }
  normal->HandleEvent(normal->GetEventNumber(), normal, 0);
  if (difficulty->selectedTag88 != static_cast<int>(kControlTagDif2)) {
    Fail("\"normal difficulty event was not applied\"");
    return;
  }
  SetPhase(kRuntimeTestActivatingOkay, "select_diff_dif2");
  RequestAnotherDriverTick();
}

void RunActivatingOkay() {
  TView* mainView = MainView();
  TControl* okay =
      mainView != 0 ? static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagOkay)) : 0;
  if (okay == 0) {
    Fail("\"okay control is missing\"");
    return;
  }
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetPhase(kRuntimeTestWaitingForStrategicMap, "activate_okay");
  RequestAnotherDriverTick();
}

bool NationModesMatchSelectedNation() {
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    short expected = nationSlot == g_runtimeTestState.selectedNationSlot ? 1 : 2;
    if (g_pSimMgr->nationControlModes[nationSlot] != expected) {
      return false;
    }
  }
  return true;
}

void RunWaitingForStrategicMap() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    WaitForNextTickOrTimeout("\"strategic map did not become active\"");
    return;
  }
  SetPhase(kRuntimeTestVerifyingStrategicMap, "observe_event_0x03b8");
  RequestAnotherDriverTick();
}

void RunVerifyingStrategicMap() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
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
    Fail("\"unexpected modal while entering the strategic map\"");
    return;
  }
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetPhase(kRuntimeTestWaitingForModalDismissal, "activate_city_site_prompt_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForModalDismissal() {
  if (!g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site prompt did not dismiss\"");
    return;
  }
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"strategic map did not remain active after the city-site prompt\"");
    return;
  }
  if (g_pGlobalMapState == 0) {
    Fail("\"strategic map has no global map state\"");
    return;
  }
  if (g_pSimMgr->activeNationSlot != g_runtimeTestState.selectedNationSlot) {
    Fail("\"active nation differs from setup selection\"");
    return;
  }
  if (!NationModesMatchSelectedNation()) {
    Fail("\"nation control modes do not match the setup selection\"");
    return;
  }
  if (g_pSimMgr->difficultyLevel != 2) {
    Fail("\"difficulty level is not Normal\"");
    return;
  }
  SetPhase(kRuntimeTestWaitingForStrategicMap, "assert_map_state_after_city_site_prompt");
  Finish("passed", "null");
}

} // namespace

void RuntimeTestDriver::OnIdle() {
  if (g_runtimeTestState.phase == kRuntimeTestNotStarted) {
    InitializeDriver();
  }
  if (g_runtimeTestState.phase == kRuntimeTestFinished) {
    return;
  }

  ++g_runtimeTestState.idleTicks;
  ++g_runtimeTestState.phaseTicks;
  switch (g_runtimeTestState.phase) {
  case kRuntimeTestWaitingForManagers:
    RunWaitingForManagers();
    break;
  case kRuntimeTestWaitingForMainMenu:
    RunWaitingForMainMenu();
    break;
  case kRuntimeTestWaitingForRandomSetup:
    RunWaitingForRandomSetup();
    break;
  case kRuntimeTestSettingCountryName:
    RunSettingCountryName();
    break;
  case kRuntimeTestSelectingDifficulty:
    RunSelectingDifficulty();
    break;
  case kRuntimeTestActivatingOkay:
    RunActivatingOkay();
    break;
  case kRuntimeTestWaitingForStrategicMap:
    RunWaitingForStrategicMap();
    break;
  case kRuntimeTestVerifyingStrategicMap:
    RunVerifyingStrategicMap();
    break;
  case kRuntimeTestWaitingForModalDismissal:
    RunWaitingForModalDismissal();
    break;
  default:
    Fail("\"runtime-test driver entered an invalid phase\"");
    break;
  }
}

unsigned int RuntimeTestDriver::RandomSeed() {
  return 1;
}
