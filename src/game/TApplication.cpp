#include "game/TAmbitApplication.h"
#include "game/TApplication.h"

#include "game/TNewGameCommand.h"
#include "game/global_data_tables.h"

#include "game/CIncludeView.h"
#include "game/ImperialismApp.h"
#include "game/TEventHandler.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00414720
void TApplication::PostTurnEventCodeMessage2420(short eventCode) {
  ::PostMessage(AfxGetMainWnd()->m_hWnd, 0x2420, eventCode, 0);
}

// SYNTHETIC: IMPERIALISM 0x00486680
// TApplication::CreateObject

// SYNTHETIC: IMPERIALISM 0x00486740
// TApplication::GetRuntimeClass

IMPLEMENT_DYNCREATE(TApplication, TCommandHandler)

// FUNCTION: IMPERIALISM 0x00486760
TApplication::TApplication()
    : TCommandHandler(), activeView(0), screenModeAt24(0), field28(0), cohandlers() {
  g_pApplicationUiRootController = this;
}

// SYNTHETIC: IMPERIALISM 0x004867b0
// TApplication::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004867e0
TApplication::~TApplication() {
  g_pApplicationUiRootController = 0;
}

// FUNCTION: IMPERIALISM 0x00486880
void TApplication::SetActiveView(TEventHandler* view) {
  this->activeView = view;
}

// FUNCTION: IMPERIALISM 0x004868a0
TEventHandler* TApplication::GetActiveView() {
  return this->activeView;
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
  AfxGetMainWnd()->PostMessage(0xbc0, 0, reinterpret_cast<LPARAM>(payload));
}

// FUNCTION: IMPERIALISM 0x00486ba0
void TApplication::vmethod_0017(int param) {}

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
  newGameCommand->InitializeRangePair(0x6e657767 /* 'gwen' */, g_pGlobalUiRootController, 0, 0, 0);
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(newGameCommand);
}
