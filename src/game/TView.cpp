// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#pragma optimize("y", on)

#include "game/TView.h"
#include "game/CString.h"
#include "game/ui_widget_shared.h"
#include "game/generated/vcall_facades.h"

// Real ctor. The scalar fields are member-initializers (not body assignments) so
// they are emitted in declaration order *before* the CString member sharedStringRef
// is constructed (-> 0x00605797), matching the original phase split. The inlined
// TEventHandler base ctor writes the base vptr (0x006497a0) + field0c; MSVC writes
// this class's vptr (0x00649858) last. No manual vtable writes — the // VTABLE:
// annotation owns it.
// FUNCTION: IMPERIALISM 0x0048a8e0
TView::TView()
    : field10(0x7fffffff), field14(0), field18(0), field20(0), field2c(0), field30(0), field3c(0),
      field44(0), field48(0), flag4c(1), flag4d(1), field4e(0xffff), field50(0), field54(1),
      sharedStringRef(), field5c(0) {}

// FUNCTION: IMPERIALISM 0x0048a9d0
TView::~TView() {
  delete reinterpret_cast<TView*>(field44);
  FreeHeapBufferIfNotNull(field48);
}

// FUNCTION: IMPERIALISM 0x00406ba9
void TView::thunk_NoOpUiLifecycleHook(int passthroughArg) {
  (void)passthroughArg;
}

// Dummy methods
void TView::vmethod_0002() {}
void TView::vmethod_0003() {}
void TView::vmethod_0004() {}
void TView::vmethod_0005() {}
void TView::vmethod_0006() {}
void TView::vmethod_0007() {}
void TView::vmethod_0008() {}
void TView::vmethod_0009() {}
void TView::vmethod_0010() {}
void TView::vmethod_0011() {}
void TView::vmethod_0012() {}
void TView::vmethod_0013() {}
void TView::vmethod_0014() {}
void TView::vmethod_0015() {}
void TView::vmethod_0016() {}
void TView::vmethod_0017() {}
void TView::vmethod_0018() {}
void TView::vmethod_0019() {}
void TView::vmethod_0020() {}
void TView::vmethod_0021() {}
void TView::vmethod_0022() {}
void TView::vmethod_0023() {}
void TView::vmethod_0024() {}
void TView::vmethod_0025() {}
void TView::vmethod_0026() {}
void TView::vmethod_0027() {}
void TView::vmethod_0028() {}
void TView::vmethod_0029() {}
void TView::vmethod_0030() {}
void TView::vmethod_0031() {}
void TView::vmethod_0032() {}
void TView::vmethod_0033() {}
void TView::vmethod_0034() {}
void TView::vmethod_0035() {}
void TView::vmethod_0036() {}
class TControl* TView::ResolveControlByTag(unsigned int controlTag) { return 0; }
void TView::vmethod_0038() {}
void TView::vmethod_0039() {}
void TView::vmethod_0040() {}
void TView::SetEnabled(int enabledState, int refreshFlag) {}
void TView::SetState(int state, int refreshFlag) {}
void TView::vmethod_0043() {}
void TView::vmethod_0044() {}
void TView::vmethod_0045() {}
void TView::vmethod_0046() {}
void TView::vmethod_0047() {}
void TView::vmethod_0048() {}
void TView::vmethod_0049() {}
void TView::vmethod_0050() {}
void TView::vmethod_0051() {}
void TView::vmethod_0052() {}
void TView::vmethod_0053() {}
void TView::vmethod_0054() {}
void TView::vmethod_0055() {}
void TView::vmethod_0056() {}
void TView::RefreshControl() {}
void TView::vmethod_0058() {}
void TView::vmethod_0059() {}
void TView::vmethod_0060() {}
void TView::vmethod_0061() {}
void TView::vmethod_0062() {}
void TView::vmethod_0063() {}
void TView::vmethod_0064() {}
void TView::vmethod_0065() {}
void TView::vmethod_0066() {}
void TView::vmethod_0067() {}
void TView::vmethod_0068() {}
void TView::vmethod_0069() {}
void TView::vmethod_0070() {}
void TView::vmethod_0071() {}
void TView::vmethod_0072() {}
void TView::vmethod_0073() {}
void TView::vmethod_0074() {}
void TView::vmethod_0075() {}
void TView::vmethod_0076() {}
void TView::vmethod_0077() {}
void TView::vmethod_0078() {}
void TView::vmethod_0079() {}
void TView::vmethod_0080() {}
void TView::vmethod_0081() {}
void TView::vmethod_0082() {}
void TView::vmethod_0083() {}
void TView::vmethod_0084() {}
void TView::vmethod_0085() {}
void TView::vmethod_0086() {}
void TView::vmethod_0087() {}
void TView::vmethod_0088() {}
void TView::vmethod_0089() {}
void TView::vmethod_0090() {}
void TView::vmethod_0091() {}
void TView::vmethod_0092() {}
void TView::vmethod_0093() {}
void TView::vmethod_0094() {}
void TView::vmethod_0095() {}
void TView::vmethod_0096() {}
void TView::vmethod_0097() {}
void TView::vmethod_0098() {}
void TView::vmethod_0099() {}
void TView::vmethod_0100() {}
void TView::vmethod_0101() {}
void TView::vmethod_0102() {}
void TView::vmethod_0103() {}
void TView::vmethod_0104() {}
void TView::vmethod_0105() {}
void TView::vmethod_0106() {}
void TView::vmethod_0107() {}
void TView::vmethod_0108() {}
void TView::vmethod_0109() {}
void TView::vmethod_0110() {}
void TView::vmethod_0111() {}
