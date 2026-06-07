// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#pragma optimize("y", on)

#include "game/TView.h"
#include "game/CString.h"
#include "game/ui_widget_shared.h"
#include "game/generated/vcall_facades.h"

#include <new>

// Real ctor. The scalar fields are member-initializers (not body assignments) so
// they are emitted in declaration order *before* the CString member sharedStringRef
// is constructed (-> 0x00605797), matching the original phase split. The inlined
// TEventHandler base ctor writes the base vptr (0x006497a0) + field0c; MSVC writes
// this class's vptr (0x00649858) last. No manual vtable writes — the // VTABLE:
// annotation owns it.
// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : field10(0x7fffffff),
      field14(0),
      field18(0),
      field20(0),
      field2c(0),
      field30(0),
      field3c(0),
      field44(0),
      field48(0),
      flag4c(1),
      flag4d(1),
      field4e(0xffff),
      field50(0),
      field54(1),
      sharedStringRef(),
      field5c(0) {}

// KNOWN LINKER ARTIFACT (heuristic 93): 0x004064e2 is a 5-byte incremental-link
// `jmp TView::TView` thunk with no clean C++ source equivalent in this non-incremental
// build — not expected to match. Do NOT chase it. The placement-new keeps base
// construction working for callers still on the bridge idiom; the durable fix is
// converting TView's derived classes to real inheritance (which retires this thunk).
// FUNCTION: IMPERIALISM 0x004064e2
void TView::thunk_ConstructUiResourceEntryBase() {
  new (this) TView();
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
