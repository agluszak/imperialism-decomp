// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#pragma optimize("y", on)

#include "game/TView.h"
#include "game/CString.h"
#include "game/ui_widget_shared.h"
#include "game/generated/vcall_facades.h"

// TView vtable (0x00649858) referenced as a data symbol so reccmp pairs the
// constructor's final vptr write (note 61: reccmp only pairs the (DATA) form,
// not raw address literals).
extern "C" char g_vtblTView = 0;

namespace {

const unsigned int kAddrVtblGetTEventHandlerClassThunk = 0x006497A0;

} // namespace

TView::TView() {
  ConstructUiResourceEntryBase();
}

// FUNCTION: IMPERIALISM 0x004064e2
void TView::thunk_ConstructUiResourceEntryBase() {
  ConstructUiResourceEntryBase();
}


// FUNCTION: IMPERIALISM 0x0048a8e0
TView* TView::ConstructUiResourceEntryBase() {
  field0c = 0;
  field10 = 0x7fffffff;
  field14 = 0;
  field18 = 0;
  *reinterpret_cast<void***>(this) = reinterpret_cast<void**>(kAddrVtblGetTEventHandlerClassThunk);
  field20 = 0;
  field2c = 0;
  field30 = 0;
  field3c = 0;
  field44 = 0;
  field48 = 0;
  flag4c = 1;
  flag4d = 1;
  field4e = 0xffff;
  field50 = 0;
  field54 = 1;
  sharedStringRef.InitFromEmpty();
  field5c = 0;
  *reinterpret_cast<void**>(this) = &g_vtblTView;
  return this;
}


// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete reinterpret_cast<TView*>(field44);
  FreeHeapBufferIfNotNull(field48);
}


// FUNCTION: IMPERIALISM 0x00406ba9
void TView::thunk_NoOpUiLifecycleHook(int passthroughArg) {
  (void)passthroughArg;
}
