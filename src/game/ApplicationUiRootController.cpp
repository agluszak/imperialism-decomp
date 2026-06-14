#include "game/ApplicationUiRootController.h"

#include "game/TView.h"
#include "game/ui_widget_thunks.h"
#include <new.h>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

int AllocateWithFallbackHandler(undefined4 size_bytes);
void __fastcall FreeLinkedBlockChain(void* blockChainHead);

extern "C" CRuntimeClass PTR_s_TApplication_00648af8;

// vtable slot 0x00 (0x00486740 via ILT): return the TApplication RTTI name pointer.
// FUNCTION: IMPERIALISM 0x00486740
CRuntimeClass* ApplicationUiRootController::GetRuntimeClass() {
  return &PTR_s_TApplication_00648af8;
}

// FUNCTION: IMPERIALISM 0x00486760
ApplicationUiRootController::ApplicationUiRootController()
    : TEventHandler(), activeView(0), screenModeAt24(0), field28(0), embeddedList() {
  g_pApplicationUiRootController = this;
}

// FUNCTION: IMPERIALISM 0x004867e0
ApplicationUiRootController::~ApplicationUiRootController() {
  g_pApplicationUiRootController = 0;
  for (void** cursor = reinterpret_cast<void**>(embeddedList.head); cursor != 0;
       cursor = reinterpret_cast<void**>(*cursor)) {
  }
  embeddedList.head = 0;
  embeddedList.field08 = 0;
  embeddedList.field0c = 0;
  embeddedList.field10 = 0;
  FreeLinkedBlockChain(reinterpret_cast<void*>(embeddedList.field14));
  embeddedList.field14 = 0;
}

// FUNCTION: IMPERIALISM 0x00486880
void ApplicationUiRootController::SetActiveView(TView* view) {
  this->activeView = view;
}

// FUNCTION: IMPERIALISM 0x004868a0
TView* ApplicationUiRootController::GetActiveView() {
  return this->activeView;
}

void ApplicationUiRootController::vmethod_0037() {}
void ApplicationUiRootController::vmethod_0038() {}
void ApplicationUiRootController::vmethod_0039() {}
void ApplicationUiRootController::vmethod_003a() {}

// FUNCTION: IMPERIALISM 0x00486680
void* __cdecl CreateTApplicationInstance(void) {
  ApplicationUiRootController* controller =
      reinterpret_cast<ApplicationUiRootController*>(AllocateWithFallbackHandler(0x48));
  if (controller == 0) {
    return 0;
  }
  new (controller) ApplicationUiRootController();
  return controller;
}
