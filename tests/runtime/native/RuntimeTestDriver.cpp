#include "RuntimeTestDriver.h"

#include "game/TDisplayMgr.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

#include <windows.h>

namespace {

enum RuntimeTestPhase {
  kRuntimeTestNotStarted,
  kRuntimeTestWaitingForManagers,
  kRuntimeTestFinished
};

struct RuntimeTestState {
  RuntimeTestPhase phase;
  unsigned long idleTicks;
  char resultPath[MAX_PATH];
};

RuntimeTestState g_runtimeTestState = {kRuntimeTestNotStarted, 0, ""};

bool RequiredManagersAreInitialized() {
  return g_pGlobalUiRootController != 0 && g_pSimMgr != 0 && g_pUiRuntimeContext != 0 &&
         g_pDisplayMgr != 0 && g_pUiViewManager != 0;
}

const char* ActiveDialogClassName() {
  if (g_pDisplayMgr == 0 || g_pDisplayMgr->activeDialog == 0) {
    return "";
  }
  CRuntimeClass* runtimeClass = g_pDisplayMgr->activeDialog->GetRuntimeClass();
  if (runtimeClass == 0 || runtimeClass->m_lpszClassName == 0) {
    return "";
  }
  return runtimeClass->m_lpszClassName;
}

void RequestAnotherDriverTick() {
  PostThreadMessageA(GetCurrentThreadId(), WM_NULL, 0, 0);
}

void RequestGameClose() {
  CWnd* mainWindow = AfxGetMainWnd();
  if (mainWindow != 0 && mainWindow->m_hWnd != 0) {
    PostMessageA(mainWindow->m_hWnd, WM_CLOSE, 0, 0);
  } else {
    PostQuitMessage(0);
  }
}

bool WriteAll(HANDLE file, const char* bytes, DWORD size) {
  DWORD written = 0;
  return WriteFile(file, bytes, size, &written, 0) != 0 && written == size;
}

bool WriteResultFile(const char* status, const char* failure) {
  CString json;
  json.Format("{\n"
              "  \"format_version\": 1,\n"
              "  \"name\": \"boot_managers\",\n"
              "  \"status\": \"%s\",\n"
              "  \"idle_ticks\": %lu,\n"
              "  \"last_action\": \"wait_for_managers\",\n"
              "  \"state\": {\n"
              "    \"active_dialog_class\": \"%s\",\n"
              "    \"display_manager\": %s,\n"
              "    \"global_ui_root\": %s,\n"
              "    \"simulation_manager\": %s,\n"
              "    \"ui_runtime_context\": %s,\n"
              "    \"ui_view_manager\": %s\n"
              "  },\n"
              "  \"runtime\": {\n"
              "    \"faults\": [],\n"
              "    \"unexpected_modals\": []\n"
              "  },\n"
              "  \"failure\": %s\n"
              "}\n",
              status, g_runtimeTestState.idleTicks, ActiveDialogClassName(),
              g_pDisplayMgr != 0 ? "true" : "false",
              g_pGlobalUiRootController != 0 ? "true" : "false", g_pSimMgr != 0 ? "true" : "false",
              g_pUiRuntimeContext != 0 ? "true" : "false", g_pUiViewManager != 0 ? "true" : "false",
              failure);

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

  if (lstrcmpA(testName, "boot_managers") != 0) {
    Finish("failed", "\"unknown compiled runtime test\"");
    return;
  }
  g_runtimeTestState.phase = kRuntimeTestWaitingForManagers;
}

} // namespace

void RuntimeTestDriver::OnIdle() {
  if (g_runtimeTestState.phase == kRuntimeTestNotStarted) {
    InitializeDriver();
  }
  if (g_runtimeTestState.phase != kRuntimeTestWaitingForManagers) {
    return;
  }

  ++g_runtimeTestState.idleTicks;
  if (RequiredManagersAreInitialized()) {
    Finish("passed", "null");
    return;
  }
  if (g_runtimeTestState.idleTicks >= 10000) {
    Finish("failed", "\"manager initialization timed out\"");
    return;
  }
  RequestAnotherDriverTick();
}
