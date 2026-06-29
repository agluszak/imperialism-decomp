#include "game/TApplication.h"

#include "game/mfc.h"
#include "game/TView.h"
#include "game/ui_widget_thunks.h"
#include <new.h>

undefined4 WrapperFor_thunk_GetTickCountDiv16_At0048a410(void);

extern "C" CRuntimeClass PTR_s_TApplication_00648af8;

// FUNCTION: IMPERIALISM 0x00486680
void* __cdecl CreateTApplicationInstance(void) {
  return new TApplication();
}

// vtable slot 0x00 (0x00486740 via ILT): return the TApplication RTTI name pointer.
IMPLEMENT_DYNCREATE(TApplication, TCommandHandler)

// FUNCTION: IMPERIALISM 0x00486760
TApplication::TApplication()
    : TCommandHandler(), activeView(0), screenModeAt24(0), field28(0), trackedEntries() {
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
// vtable slot 0x28 (0x00486990 via ILT 0x00405551): original body is `RET 0xc` (takes
// three stack args, does nothing). A no-op hook for viewport-edge auto-scroll handling.

// FUNCTION: IMPERIALISM 0x00486990
void TApplication::HandleTurnEventViewportEdgeAutoScroll(int arg1, int arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// vtable slot 0x29 (0x004869b0): add/remove an entry from the embedded MFC list.

// FUNCTION: IMPERIALISM 0x004869b0
void TApplication::InsertOrRemoveTrackedEntry(int value, char insertFlag) {
  if (insertFlag != 0) {
    trackedEntries.AddHead(reinterpret_cast<void*>(value));
    return;
  }

  POSITION match = trackedEntries.Find(reinterpret_cast<void*>(value));
  if (match != 0) {
    trackedEntries.RemoveAt(match);
  }
}

// vtable slot 0x2a (0x00486b10 via ILT 0x00403f21): walk the tracked entries and invoke
// each receiver's tick method with `arg`.

// FUNCTION: IMPERIALISM 0x00486b10
void TApplication::TickEachTrackedEntry(int arg) {
  POSITION pos = trackedEntries.GetHeadPosition();
  while (pos != 0) {
    int entry = reinterpret_cast<int>(trackedEntries.GetNext(pos));
    reinterpret_cast<void(__fastcall*)(int, int, int)>(
        reinterpret_cast<void (*)()>(WrapperFor_thunk_GetTickCountDiv16_At0048a410))(entry, 0, arg);
  }
}

// FUNCTION: IMPERIALISM 0x00486b50
void TApplication::DispatchQueuedUiCommandAndRelease(void* payload) {}

// FUNCTION: IMPERIALISM 0x00486ba0
void TApplication::vmethod_0017(int param) {}
