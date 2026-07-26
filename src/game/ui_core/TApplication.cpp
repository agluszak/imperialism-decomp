#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TApplication.h"

#include "game/pointer_representation.h"

#include "game/gfx/TNewGameCommand.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

#include "game/ui_core/CIncludeView.h"
#include "game/ImperialismApp.h"
#include "game/ui_core/TEventHandler.h"
#include "game/mfc.h"

// Post WM_CLOSE to the main thread's window. Faithful to the original: when
// AfxGetThread() returns null the main-window pointer stays null and the m_hWnd
// read dereferences it unguarded (latent original bug, kept as-is).
// FUNCTION: IMPERIALISM 0x004146d0
void TApplication::PostWmCloseToMainThreadWindow() {
  CWnd* mainWindow = AfxGetThread() != 0 ? AfxGetThread()->GetMainWnd() : 0;
  ::PostMessage(mainWindow->m_hWnd, WM_CLOSE, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00414720
void TApplication::PostTurnEventCodeMessage2420(TurnEventCodeStorage eventCode) {
  ::PostMessage(AfxGetMainWnd()->m_hWnd, 0x2420, eventCode, 0);
}

// SYNTHETIC: IMPERIALISM 0x00486680
// TApplication::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486740
// TApplication::GetRuntimeClass

IMPLEMENT_DYNCREATE(TApplication, TCommandHandler)

// FUNCTION: IMPERIALISM 0x00486760
TApplication::TApplication()
    : TCommandHandler(), currentTarget(0), screenModeAt24(0), cohandlers() {
  g_pApplicationUiRootController = this;
}

// SYNTHETIC: IMPERIALISM 0x004867b0
// TApplication::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004867e0
TApplication::~TApplication() {
  g_pApplicationUiRootController = 0;
}

// FUNCTION: IMPERIALISM 0x00486880
void TApplication::SetTarget(TEventHandler* view) {
  this->currentTarget = view;
}

// FUNCTION: IMPERIALISM 0x004868a0
TEventHandler* TApplication::GetTarget() {
  return this->currentTarget;
}

// vtable slot 0x25 is inherited from TCommandHandler: process a queued command through
// its slot 0x0b and then release it through slot 0x07.

// vtable slot 0x28 (0x00486990 via ILT 0x00405551): `RET 0xc` no-op. MacApp's
// FUNCTION: IMPERIALISM 0x00486960
BOOL TApplication::InModalState() {
  return GetMainViewHostFromActiveThread()->GetUiInteractiveFlag90() == 0;
}
// TApplication::GetDefaultCursorRegion(CPoint, Region**) — the Windows port keeps the
// hook (TAmbitApplication::HandleCursor tail-calls it) but computes no region.
// FUNCTION: IMPERIALISM 0x00486990
void TApplication::GetDefaultCursorRegion(int x, int y, void* cursorRegion) {
  (void)x;
  (void)y;
  (void)cursorRegion;
}

// vtable slot 0x29 (0x004869b0): MacApp TApplication::InstallCohandler — register or
// remove a TEventHandler on the idle cohandler list at +0x2c.
// FUNCTION: IMPERIALISM 0x004869b0
void TApplication::InstallCohandler(TEventHandler* cohandler, unsigned char install) {
  if (install != 0) {
    cohandlers.AddHead(cohandler);
    return;
  }

  POSITION match = cohandlers.Find(cohandler);
  if (match != 0) {
    cohandlers.RemoveAt(match);
  }
}

// vtable slot 0x2a (0x00486b10 via ILT 0x00403f21): MacApp TApplication::Idle — give
// every installed cohandler its throttled idle tick.
// FUNCTION: IMPERIALISM 0x00486b10
void TApplication::Idle(int idlePhase) {
  POSITION pos = cohandlers.GetHeadPosition();
  while (pos != 0) {
    TEventHandler* cohandler = static_cast<TEventHandler*>(cohandlers.GetNext(pos));
    cohandler->HandleIdle(idlePhase);
  }
}

// MacApp TApplication::InModalState(): TRUE while the main view host's +0x90
// interactive flag is clear. Callers (always through g_pApplicationUiRootController or
// this) bail out of cursor auto-scroll / nav-command handling while it holds. Reads
// nothing from `this`; the original dereferences the view host unguarded.

// FUNCTION: IMPERIALISM 0x00486b50
void TApplication::DispatchQueuedUiCommandAndRelease(void* payload) {
  AfxGetMainWnd()->PostMessage(0xbc0, 0, PointerAddressLong32(payload));
}

// FUNCTION: IMPERIALISM 0x00486ba0
void TApplication::DoMenuCommand(int command) {
  CWnd* mainWindow;

  // Case bodies follow their order in the retail jump table. VC5 preserves source
  // order here, so keeping this order also preserves the original layout.
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

// TApplication::cohandlers' compiler-emitted CList<void*,void*>::Serialize body.
// The real source is the embedded cohandlers template list, not a TApplication vtable slot.
// TEMPLATE: IMPERIALISM 0x00486df0
// ?Serialize@?$CList@PAXPAX@@UAEXAAVCArchive@@@Z

// TEMPLATE: IMPERIALISM 0x00486f60
// ??_G?$CList@PAXPAX@@UAEPAXI@Z

// TEMPLATE: IMPERIALISM 0x00486f90
// ??1?$CList@PAXPAX@@UAE@XZ

// FUNCTION: IMPERIALISM 0x0049e500
void TApplication::CreateAndQueueTurnEventPacketTagGWEN() {
  // Build a TNewGameCommand, tag it 'gwen' targeting the global UI root controller,
  // and dispatch it.
  TNewGameCommand* newGameCommand = new TNewGameCommand();
  newGameCommand->ICommand(kControlTagNewg, g_pGlobalUiRootController, 0, 0, 0);
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(newGameCommand);
}
