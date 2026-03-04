// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TView.h"
#include "game/string_shared.h"

namespace {

const unsigned int kAddrVtblTView = 0x00649858;
const unsigned int kAddrVtblGetTEventHandlerClassThunk = 0x006497A0;

} // namespace

// FUNCTION: IMPERIALISM 0x004064e2
void TView::thunk_ConstructUiResourceEntryBase() {
  ConstructUiResourceEntryBase();
}

// FUNCTION: IMPERIALISM 0x0048a8e0
void TView::ConstructUiResourceEntryBase() {
  field0c = 0;
  field10 = 0x7fffffff;
  field14 = 0;
  field18 = 0;
  vftable = reinterpret_cast<void*>(kAddrVtblGetTEventHandlerClassThunk);
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
  reinterpret_cast<StringShared*>(&sharedStringRef)->InitFromEmpty();
  field5c = 0;
  vftable = reinterpret_cast<void*>(kAddrVtblTView);
}
