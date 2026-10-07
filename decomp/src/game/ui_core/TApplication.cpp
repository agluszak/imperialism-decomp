#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TApplication.h"

#include "game/pointer_representation.h"

#include "game/gfx/TNewGameCommand.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include "game/ui_core/CIncludeView.h"
#include "game/ImperialismApp.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TWindow.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x004146b0
void __stdcall CloseWindowAndFree(TWindow* window) {
  window->CloseAndFree();
}

// FUNCTION: IMPERIALISM 0x004146d0
void TApplication::PostWmCloseToMainThreadWindow() {
  CWnd* mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
  ::PostMessage(mainWindow->m_hWnd, WM_CLOSE, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00414720
void TApplication::PostTurnEventCodeMessage(TurnEventCodeStorage eventCode) {
  ::PostMessage(AfxGetMainWnd()->m_hWnd, 0x2420, eventCode, 0);
}

IMPLEMENT_DYNCREATE(TApplication, TCommandHandler)

// FUNCTION: IMPERIALISM 0x00486760
TApplication::TApplication() : currentTarget(0), screenMode(0) {
  g_pApplication = this;
}

// FUNCTION: IMPERIALISM 0x004867e0
TApplication::~TApplication() {
  g_pApplication = 0;
}

// FUNCTION: IMPERIALISM 0x00486880
void TApplication::SetTarget(TEventHandler* view) {
  currentTarget = view;
}

// FUNCTION: IMPERIALISM 0x004868a0
TEventHandler* TApplication::GetTarget() {
  return currentTarget;
}

// vtable slot 0x28 (0x00486990 via ILT 0x00405551): `RET 0xc` no-op. MacApp's
// FUNCTION: IMPERIALISM 0x00486960
BOOL TApplication::InModalState() {
  return GetMainViewHostFromActiveThread()->GetUiInteractiveFlag() == 0;
}
// FUNCTION: IMPERIALISM 0x00486990
void TApplication::GetDefaultCursorRegion(int x, int y, void* cursorRegion) {}

// FUNCTION: IMPERIALISM 0x004869b0
void TApplication::InstallCohandler(TEventHandler* cohandler, bool install) {
  if (install) {
    cohandlers.AddHead(cohandler);
    return;
  }

  POSITION match = cohandlers.Find(cohandler);
  if (match != 0) {
    cohandlers.RemoveAt(match);
  }
}

// FUNCTION: IMPERIALISM 0x00486b10
void TApplication::Idle(int idlePhase) {
  POSITION pos = cohandlers.GetHeadPosition();
  while (pos != 0) {
    TEventHandler* cohandler = static_cast<TEventHandler*>(cohandlers.GetNext(pos));
    cohandler->HandleIdle(idlePhase);
  }
}

// ORACLE: MacApp TApplication::InModalState(); `this` is unused.

// FUNCTION: IMPERIALISM 0x00486b50
void TApplication::DispatchQueuedUiCommandAndRelease(void* payload) {
  AfxGetMainWnd()->PostMessage(0xbc0, 0, PointerAddressLong32(payload));
}

// FUNCTION: IMPERIALISM 0x00486ba0
void TApplication::DoMenuCommand(int command) {
  CWnd* mainWindow;

  switch (command) {
  case 0x24:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_CLOSE, 0, 0);
    return;

  case 0x0a:
  case 0x0b:
  case 0x0c:
  case 0x0d:
  case 0x0e:
  case 0x0f:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_COMMAND, 0xe100, 0);
    return;

  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
  case 0x1c:
  case 0x1d:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_COMMAND, 0xe101, 0);
    return;

  case 0x1e:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_COMMAND, 0xe103, 0);
    return;

  case 0x20:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_COMMAND, 0xe104, 0);
    return;

  case 0x1f:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_COMMAND, 0xe102, 0);
    return;

  case 1:
    mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
    ::PostMessage(mainWindow->m_hWnd, WM_COMMAND, 0xe140, 0);
    return;

  default:
    TEventHandler::DoMenuCommand(command);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x0049e500
void TApplication::CreateAndQueueTurnEventPacketTagGWEN() {
  TNewGameCommand* newGameCommand = new TNewGameCommand();
  newGameCommand->ICommand(kControlTagNewg, g_pAmbitApplication, 0, 0, 0);
  g_pAmbitApplication->DispatchUiSelectionToHandler(newGameCommand);
}
