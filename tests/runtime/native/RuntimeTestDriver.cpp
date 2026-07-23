#include "RuntimeTestDriver.h"

#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/CIncludeView.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/map_ui/TCitySiteView.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TGameSetupPicture.h"
#include "game/ImperialismApp.h"
#include "game/map/TMapUberPicture.h"
#include "game/map/TMapMgr.h"
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
#include "game/ui_control_tags.h"

#include <stdlib.h>
#include <windows.h>

namespace {

enum RuntimeTestKind {
  kRuntimeTestNone,
  kRuntimeTestBootManagers,
  kRuntimeTestRandomGame,
  kRuntimeTestEasyRandomGame
};

enum RuntimeTestPhase {
  kRuntimeTestNotStarted,
  kRuntimeTestWaitingForManagers,
  kRuntimeTestWaitingForMainMenu,
  kRuntimeTestWaitingForRandomSetup,
  kRuntimeTestSettingCountryName,
  kRuntimeTestSelectingDifficulty,
  kRuntimeTestActivatingOkay,
  kRuntimeTestWaitingForEasyStrategicMap,
  kRuntimeTestWaitingForStrategicMap,
  kRuntimeTestVerifyingStrategicMap,
  kRuntimeTestWaitingForModalDismissal,
  kRuntimeTestPrimingMapHover,
  kRuntimeTestDispatchingMapHotkey,
  kRuntimeTestExercisingMapHover,
  kRuntimeTestReturningToRandomSetup,
  kRuntimeTestReturningToMainMenu,
  kRuntimeTestReenteringRandomSetup,
  kRuntimeTestVerifyingReturnedRandomSetup,
  kRuntimeTestWaitingForSecondCitySite,
  kRuntimeTestWaitingForSecondPromptDismissal,
  kRuntimeTestWaitingForCitySiteConfirmation,
  kRuntimeTestWaitingForCombinedMap,
  kRuntimeTestVerifyingCombinedMapExtents,
  kRuntimeTestFinished
};

struct RuntimeTestState {
  RuntimeTestKind kind;
  RuntimeTestPhase phase;
  unsigned long idleTicks;
  unsigned long phaseTicks;
  short selectedNationSlot;
  HWND mainWindowHandle;
  bool newspaperAdvanced;
  char resultPath[MAX_PATH];
  char lastAction[64];
};

RuntimeTestState g_runtimeTestState = {
    kRuntimeTestNone, kRuntimeTestNotStarted, 0, 0, -1, 0, false, "", ""};
CString g_randomSetupUiSnapshot;
CString g_strategicMapUiSnapshot;
CString g_capitalConfirmationUiSnapshot;
CString g_activatedEventSequence("[");

bool IsRandomGameTest() {
  return g_runtimeTestState.kind == kRuntimeTestRandomGame ||
         g_runtimeTestState.kind == kRuntimeTestEasyRandomGame;
}

const char* TestName() {
  if (g_runtimeTestState.kind == kRuntimeTestEasyRandomGame) {
    return "random_game_easy_skips_capital";
  }
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

void AppendJsonString(CString& json, const char* value) {
  json += '"';
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor != 0;
       ++cursor) {
    char escaped[7];
    switch (*cursor) {
    case '"':
      json += "\\\"";
      break;
    case '\\':
      json += "\\\\";
      break;
    case '\n':
      json += "\\n";
      break;
    case '\r':
      json += "\\r";
      break;
    case '\t':
      json += "\\t";
      break;
    default:
      if (*cursor < 0x20) {
        wsprintfA(escaped, "\\u%04x", static_cast<unsigned int>(*cursor));
        json += escaped;
      } else {
        json += static_cast<char>(*cursor);
      }
      break;
    }
  }
  json += '"';
}

void FourCcText(unsigned int tag, char text[5]) {
  text[0] = static_cast<char>(tag >> 24);
  text[1] = static_cast<char>(tag >> 16);
  text[2] = static_cast<char>(tag >> 8);
  text[3] = static_cast<char>(tag);
  text[4] = 0;
}

int TagOccurrenceBefore(TView* parent, TView* target) {
  if (parent == 0 || parent->childList44 == 0) {
    return 1;
  }
  int occurrence = 1;
  POSITION position = parent->childList44->GetHeadPosition();
  while (position != 0) {
    TView* sibling = parent->childList44->GetNext(position);
    if (sibling == target) {
      break;
    }
    if (sibling->controlTag == target->controlTag) {
      ++occurrence;
    }
  }
  return occurrence;
}

CString ViewPath(TView* view, const CString& parentPath) {
  CString path;
  path.Format("%08x#%d", static_cast<unsigned int>(view->controlTag),
              TagOccurrenceBefore(view->ownerContext, view));
  if (!parentPath.IsEmpty()) {
    path = parentPath + "/" + path;
  }
  return path;
}

void AppendViewTreeNodes(CString& json, TView* view, const CString& parentPath, bool& firstNode) {
  if (view == 0) {
    return;
  }
  CString path = ViewPath(view, parentPath);
  char tag[5];
  FourCcText(static_cast<unsigned int>(view->controlTag), tag);
  if (!firstNode) {
    json += ",\n";
  }
  firstNode = false;
  json += "      {\"path\": ";
  AppendJsonString(json, path);
  json += ", \"parent\": ";
  if (parentPath.IsEmpty()) {
    json += "null";
  } else {
    AppendJsonString(json, parentPath);
  }
  json += ", \"tag\": ";
  AppendJsonString(json, tag);
  json += ", \"class\": ";
  AppendJsonString(json, RuntimeClassName(view));
  CString fields;
  fields.Format(", \"bounds\": [%d, %d, %d, %d], \"absolute\": [%d, %d], \"state\": %d, "
                "\"enabled\": %d, \"control_value\": %d",
                view->ownerLocalX, view->ownerLocalY, view->frameWidth34, view->frameHeight38,
                view->absoluteX, view->absoluteY, view->field04, view->field08,
                view->controlValue3c);
  json += fields;
  if (view->IsKindOf(RUNTIME_CLASS(TPicture)) != 0) {
    TPicture* picture = static_cast<TPicture*>(view);
    fields.Format(", \"picture_id\": %d", static_cast<int>(picture->glyphBase84));
    json += fields;
  }
  if (view->IsKindOf(RUNTIME_CLASS(TStaticText)) != 0) {
    TStaticText* text = static_cast<TStaticText*>(view);
    json += ", \"text\": ";
    AppendJsonString(json, text->text != 0 ? static_cast<LPCSTR>(*text->text) : "");
  }
  json += "}";

  if (view->childList44 == 0) {
    return;
  }
  POSITION position = view->childList44->GetHeadPosition();
  while (position != 0) {
    TView* child = view->childList44->GetNext(position);
    AppendViewTreeNodes(json, child, path, firstNode);
  }
}

CString CaptureUiSnapshot(int eventCode, TView* root) {
  CString json;
  CString header;
  header.Format("    {\"event\": %d, \"nodes\": [\n", eventCode);
  json += header;
  bool firstNode = true;
  AppendViewTreeNodes(json, root, CString(), firstNode);
  json += "\n    ]}";
  return json;
}

bool WriteResultFile(const char* status, const char* failure) {
  TView* mainView = MainView();
  CString eventSequence(g_activatedEventSequence);
  eventSequence += ']';
  const char* handledModals =
      g_runtimeTestState.kind == kRuntimeTestRandomGame
          ? "[\"city_site_prompt\", \"city_site_prompt\", \"city_site_confirmation\"]"
          : "[]";
  if (IsRandomGameTest() &&
      (g_randomSetupUiSnapshot.IsEmpty() || g_strategicMapUiSnapshot.IsEmpty())) {
    status = "failed";
    failure = "\"generated UI factory snapshot is missing\"";
  }
  CString uiSnapshots("[");
  if (IsRandomGameTest()) {
    if (!g_randomSetupUiSnapshot.IsEmpty()) {
      uiSnapshots += "\n";
      uiSnapshots += g_randomSetupUiSnapshot;
    }
    if (!g_strategicMapUiSnapshot.IsEmpty()) {
      if (!g_randomSetupUiSnapshot.IsEmpty()) {
        uiSnapshots += ",";
      }
      uiSnapshots += "\n";
      uiSnapshots += g_strategicMapUiSnapshot;
    }
    uiSnapshots += "\n  ";
  }
  uiSnapshots += "]";
  CString capitalConfirmationSnapshot("null");
  if (!g_capitalConfirmationUiSnapshot.IsEmpty()) {
    capitalConfirmationSnapshot = g_capitalConfirmationUiSnapshot;
  }
  CString json;
  json.Format("{\n"
              "  \"format_version\": 1,\n"
              "  \"name\": \"%s\",\n"
              "  \"status\": \"%s\",\n"
              "  \"idle_ticks\": %lu,\n"
              "  \"last_action\": \"%s\",\n"
              "  \"event_sequence\": %s,\n"
              "  \"ui_snapshots\": %s,\n"
              "  \"capital_confirmation_snapshot\": %s,\n"
              "  \"state\": {\n"
              "    \"turn_event\": %d,\n"
              "    \"root_class\": \"%s\",\n"
              "    \"active_nation\": %d,\n"
              "    \"selected_nation\": %d,\n"
              "    \"difficulty\": %d,\n"
              "    \"multiplayer_role\": %d,\n"
              "    \"turn_state\": %d,\n"
              "    \"mode\": %d,\n"
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
              static_cast<LPCSTR>(eventSequence), static_cast<LPCSTR>(uiSnapshots),
              static_cast<LPCSTR>(capitalConfirmationSnapshot),
              g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1,
              RuntimeClassName(mainView), g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1,
              g_runtimeTestState.selectedNationSlot,
              g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1,
              g_pSimMgr != 0 ? g_pSimMgr->multiplayerSessionRole : -1,
              g_pSimMgr != 0 ? g_pSimMgr->turnStateCode : -1, g_pSimMgr != 0 ? g_pSimMgr->mode : -1,
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
  char holdOpen[2];
  if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_HOLD", holdOpen, sizeof(holdOpen)) != 0) {
    return;
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
  } else if (lstrcmpA(testName, "random_game_easy_skips_capital") == 0) {
    g_runtimeTestState.kind = kRuntimeTestEasyRandomGame;
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

bool ClickViewThroughNativeHost(TView* view) {
  CIncludeView* host = GetMainViewHostFromActiveThread();
  if (view == 0 || host == 0 || host->m_hWnd == 0) {
    return false;
  }

  CPoint position;
  view->GetAbsolutePosition(&position);
  position.x += view->frameWidth34 / 2;
  position.y += view->frameHeight38 / 2;
  LPARAM mousePosition = MAKELPARAM(position.x, position.y);
  SendMessageA(host->m_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, mousePosition);
  SendMessageA(host->m_hWnd, WM_LBUTTONUP, 0, mousePosition);
  return true;
}

void RunWaitingForMainMenu() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not become active\"");
    return;
  }

  srand(RuntimeTestDriver::RandomSeed());
  TView* randomButton = mainView->ResolveControlByTag(kControlTagRand);
  if (!ClickViewThroughNativeHost(randomButton)) {
    Fail("\"main-menu random-game button or native host is missing\"");
    return;
  }
  SetPhase(kRuntimeTestWaitingForRandomSetup, "click_main_menu_rand");
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
  const unsigned long expectedTag =
      g_runtimeTestState.kind == kRuntimeTestEasyRandomGame ? kControlTagDif1 : kControlTagDif2;
  TControl* option =
      difficulty != 0 ? static_cast<TControl*>(difficulty->ResolveControlByTag(expectedTag)) : 0;
  if (difficulty == 0 || option == 0) {
    Fail("\"requested difficulty control is missing\"");
    return;
  }
  if (g_runtimeTestState.kind == kRuntimeTestEasyRandomGame) {
    if (!ClickViewThroughNativeHost(option)) {
      Fail("\"easy difficulty control or native host is missing\"");
      return;
    }
  } else {
    option->HandleEvent(option->GetEventNumber(), option, 0);
  }
  if (difficulty->selectedTag88 != static_cast<int>(expectedTag)) {
    Fail("\"requested difficulty event was not applied\"");
    return;
  }
  SetPhase(kRuntimeTestActivatingOkay, g_runtimeTestState.kind == kRuntimeTestEasyRandomGame
                                           ? "click_diff_dif1"
                                           : "select_diff_dif2");
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
  if (g_runtimeTestState.kind == kRuntimeTestEasyRandomGame) {
    if (!ClickViewThroughNativeHost(okay)) {
      Fail("\"okay control or native host is missing\"");
      return;
    }
    SetPhase(kRuntimeTestWaitingForEasyStrategicMap, "click_okay");
  } else {
    okay->HandleEvent(okay->GetEventNumber(), okay, 0);
    SetPhase(kRuntimeTestWaitingForStrategicMap, "activate_okay");
  }
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

bool AdvanceInitialNewspaperIfNeeded() {
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x2103) {
    return false;
  }
  TView* mainView = MainView();
  if (!IsViewKindOf(mainView, RUNTIME_CLASS(TNewspaperView))) {
    Fail("\"event 0x2103 did not construct the newspaper view\"");
    return true;
  }
  if (g_runtimeTestState.newspaperAdvanced) {
    WaitForNextTickOrTimeout("\"newspaper end action did not advance to the combined map\"");
    return true;
  }
  TControl* endControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagEnd));
  if (endControl == 0 || endControl->IsActionable() == 0) {
    Fail("\"newspaper end control is missing or disabled\"");
    return true;
  }
  g_runtimeTestState.newspaperAdvanced = true;
  lstrcpynA(g_runtimeTestState.lastAction, "activate_newspaper_end",
            sizeof(g_runtimeTestState.lastAction));
  endControl->HandleEvent(endControl->GetEventNumber(), endControl, 0);
  RequestAnotherDriverTick();
  return true;
}

void RunWaitingForEasyStrategicMap() {
  const int eventCode = g_pUiRuntimeContext->currentTurnEventCode;
  if (eventCode == 0x3b8) {
    Fail("\"Easy difficulty incorrectly entered capital-site selection\"");
    return;
  }
  if (eventCode == 0x5e4) {
    Fail("\"single-player Easy game incorrectly entered multiplayer synchronization\"");
    return;
  }
  if (AdvanceInitialNewspaperIfNeeded()) {
    return;
  }
  TView* mainView = MainView();
  if (eventCode != 0x7dd || !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    WaitForNextTickOrTimeout("\"Easy random game did not reach the combined strategic map\"");
    return;
  }
  if (!g_ModalViewStack.IsEmpty()) {
    Fail("\"Easy random game unexpectedly displayed a modal capital prompt\"");
    return;
  }
  if (g_pSimMgr->difficultyLevel != 1) {
    Fail("\"native Easy selection did not store difficulty level 1\"");
    return;
  }
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    Fail("\"single-player Easy game has a multiplayer session role\"");
    return;
  }
  if (!NationModesMatchSelectedNation()) {
    Fail("\"nation control modes do not match the Easy setup selection\"");
    return;
  }
  Finish("passed", "null");
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
  const char* holdPhase = getenv("IMPERIALISM_RUNTIME_TEST_HOLD");
  if (holdPhase != 0 && lstrcmpiA(holdPhase, "capital") != 0) {
    RedrawWindow(mapView->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    Finish("passed", "null");
    return;
  }
  SetPhase(kRuntimeTestPrimingMapHover, "prime_city_site_hover");
  RequestAnotherDriverTick();
}

void RunPrimingMapHover() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"strategic map has no city-site hover view\"");
    return;
  }

  mapDialog->RefreshControl();
  mapDialog->ForceRedraw();
  CPoint point(256, 224);
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&point, 0);
  short paintedTile = static_cast<short>(mapDialog->paintedHoverTileIndex6e);
  signed char markerIndex = g_pGlobalMapState->terrainStateTable[paintedTile].markerSlotIndex10;
  if (markerIndex == -1 || mapDialog->tileMarkers7c[markerIndex].flag == 0) {
    Fail("\"primed city-site hover tile is not present in the render cache\"");
    return;
  }
  SetPhase(kRuntimeTestDispatchingMapHotkey, "forward_map_hotkey_x");
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
  short finalTile = static_cast<short>(g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(
      g_runtimeTestState.selectedNationSlot));
  for (short tile = 0; tile < 0x1950; ++tile) {
    const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
    if (terrain.GetTerrainKind() == kStrategicTerrainMountain &&
        terrain.ownerNationTag04 == g_runtimeTestState.selectedNationSlot) {
      finalTile = tile;
      break;
    }
  }
  citySiteView->SetMapViewTileIndex(finalTile);
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(MainView(), RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"map hotkey forwarding left the strategic map\"");
    return;
  }
  SetPhase(kRuntimeTestExercisingMapHover, "exercise_city_site_hover");
  RequestAnotherDriverTick();
}

void RunExercisingMapHover() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
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
  if (!ClickViewThroughNativeHost(cancel)) {
    Fail("\"strategic-map return button or native host is missing\"");
    return;
  }
  SetPhase(kRuntimeTestReturningToRandomSetup, "click_strategic_map_canc");
  RequestAnotherDriverTick();
}

void RunReturningToRandomSetup() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random setup did not return after leaving the strategic map\"");
    return;
  }

  TView* cancel = mainView->ResolveControlByTag(kControlTagCncl);
  if (!ClickViewThroughNativeHost(cancel)) {
    Fail("\"returned random setup main-menu button or native host is missing\"");
    return;
  }
  SetPhase(kRuntimeTestReturningToMainMenu, "click_returned_setup_cncl");
  RequestAnotherDriverTick();
}

void RunReturningToMainMenu() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not return after leaving random setup\"");
    return;
  }

  TView* randomButton = mainView->ResolveControlByTag(kControlTagRand);
  if (!ClickViewThroughNativeHost(randomButton)) {
    Fail("\"returned main-menu random-game button or native host is missing\"");
    return;
  }
  SetPhase(kRuntimeTestReenteringRandomSetup, "click_returned_main_menu_rand");
  RequestAnotherDriverTick();
}

void RunReenteringRandomSetup() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random setup did not reopen from the returned main menu\"");
    return;
  }

  TView* hard = mainView->ResolveControlByTag(kControlTagDif3);
  if (!ClickViewThroughNativeHost(hard)) {
    Fail("\"reopened random setup difficulty control or native host is missing\"");
    return;
  }
  SetPhase(kRuntimeTestVerifyingReturnedRandomSetup, "click_reopened_setup_dif3");
  RequestAnotherDriverTick();
}

void RunVerifyingReturnedRandomSetup() {
  TView* mainView = MainView();
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
  SetPhase(kRuntimeTestWaitingForSecondCitySite, "activate_reopened_setup_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForSecondCitySite() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture)) || g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"second city-site selector or prompt did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (okay == 0) {
    Fail("\"second city-site prompt has no okay control\"");
    return;
  }
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetPhase(kRuntimeTestWaitingForSecondPromptDismissal, "activate_second_city_site_prompt_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForSecondPromptDismissal() {
  if (!g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"second city-site prompt did not dismiss\"");
    return;
  }

  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
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
    if (supportsCity && tile.ownerNationTag04 == g_runtimeTestState.selectedNationSlot &&
        tile.recruitSearchVisited0e == 0) {
      citySite = tileIndex;
      break;
    }
  }
  if (citySite == -1) {
    Fail("\"random map has no valid city-site candidate for the selected nation\"");
    return;
  }

  SetPhase(kRuntimeTestWaitingForCitySiteConfirmation, "submit_valid_city_site");
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
  g_capitalConfirmationUiSnapshot = CaptureUiSnapshot(0x3b9, modal);
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
  SetPhase(kRuntimeTestWaitingForCombinedMap, "accept_city_site_confirmation");
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
  if (mapDialog == 0 || IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"combined map retained the country-bounded city-site view\"");
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
  case kRuntimeTestWaitingForEasyStrategicMap:
    RunWaitingForEasyStrategicMap();
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
  case kRuntimeTestPrimingMapHover:
    RunPrimingMapHover();
    break;
  case kRuntimeTestDispatchingMapHotkey:
    RunDispatchingMapHotkey();
    break;
  case kRuntimeTestExercisingMapHover:
    RunExercisingMapHover();
    break;
  case kRuntimeTestReturningToRandomSetup:
    RunReturningToRandomSetup();
    break;
  case kRuntimeTestReturningToMainMenu:
    RunReturningToMainMenu();
    break;
  case kRuntimeTestReenteringRandomSetup:
    RunReenteringRandomSetup();
    break;
  case kRuntimeTestVerifyingReturnedRandomSetup:
    RunVerifyingReturnedRandomSetup();
    break;
  case kRuntimeTestWaitingForSecondCitySite:
    RunWaitingForSecondCitySite();
    break;
  case kRuntimeTestWaitingForSecondPromptDismissal:
    RunWaitingForSecondPromptDismissal();
    break;
  case kRuntimeTestWaitingForCitySiteConfirmation:
    RunWaitingForCitySiteConfirmation();
    break;
  case kRuntimeTestWaitingForCombinedMap:
    RunWaitingForCombinedMap();
    break;
  case kRuntimeTestVerifyingCombinedMapExtents:
    RunVerifyingCombinedMapExtents();
    break;
  default:
    Fail("\"runtime-test driver entered an invalid phase\"");
    break;
  }
}

void RuntimeTestDriver::ObserveBuiltUiTree(int eventCode, TView* root) {
  if (!IsRandomGameTest()) {
    return;
  }
  if (eventCode == 0x5dd) {
    g_randomSetupUiSnapshot = CaptureUiSnapshot(eventCode, root);
  } else if (eventCode == 0x3b8 ||
             (g_runtimeTestState.kind == kRuntimeTestEasyRandomGame && eventCode == 0x7dd)) {
    g_strategicMapUiSnapshot = CaptureUiSnapshot(eventCode, root);
  }
}

void RuntimeTestDriver::ObserveActivatedTurnEvent(int eventCode) {
  if (IsRandomGameTest()) {
    CString event;
    event.Format("%s\"0x%04x\"", g_activatedEventSequence.GetLength() == 1 ? "" : ", ",
                 static_cast<unsigned short>(eventCode));
    g_activatedEventSequence += event;
  }
  if (IsRandomGameTest() && g_pSimMgr != 0 && g_pSimMgr->multiplayerSessionRole == 0 &&
      eventCode == 0x5e4) {
    Fail("\"single-player game entered multiplayer synchronization event 0x5e4\"");
    return;
  }
  if (g_runtimeTestState.kind == kRuntimeTestEasyRandomGame && eventCode == 0x3b8) {
    Fail("\"Easy difficulty entered capital-site selection event 0x3b8\"");
    return;
  }
  if (g_runtimeTestState.kind != kRuntimeTestRandomGame ||
      (g_runtimeTestState.phase != kRuntimeTestWaitingForCitySiteConfirmation &&
       g_runtimeTestState.phase != kRuntimeTestWaitingForCombinedMap)) {
    return;
  }
  if (eventCode != 0x7dd) {
    return;
  }
  SetPhase(kRuntimeTestVerifyingCombinedMapExtents, "observe_event_0x07dd");
  RunVerifyingCombinedMapExtents();
}

unsigned int RuntimeTestDriver::RandomSeed() {
  return 1;
}

void RuntimeTestObserveBuiltUiTree(int eventCode, TView* root) {
  RuntimeTestDriver::ObserveBuiltUiTree(eventCode, root);
}
