#include "game/TWindow.h"
#include "game/mcappui_globals.h"

extern "C" CRuntimeClass PTR_s_TWindow_006495e8;

undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);

// One-shot McAppUI invalidation-flag assert. The original reaches the shared invalidation
// helper through the incremental-link thunk; each call site is gated by its own
// g_McAppUiFlag_* one-shot so the assert fires at most once.
static __inline void AssertMcAppUiInvalidation(const char* path, int line) {
  reinterpret_cast<void(__cdecl*)(const char*, int)>(
      thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(path, line);
}

// FUNCTION: IMPERIALISM 0x0048d220
CRuntimeClass* TWindow::GetRuntimeClass() const {
  return &PTR_s_TWindow_006495e8;
}

// SYNTHETIC: IMPERIALISM 0x0048d640
// TWindow::`scalar deleting destructor'
TWindow::~TWindow() {}

// FUNCTION: IMPERIALISM 0x0048d8a0
void TWindow::SetField88And8c(int param_1, int param_2) {
  field88 = param_1;
  field8c = param_2;
}

// FUNCTION: IMPERIALISM 0x0048d8d0
void TWindow::AssertMcAppUILine2358() {
  if (g_McAppUiFlag_006A1B04 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0x936);
  }
}

// FUNCTION: IMPERIALISM 0x0048d900
undefined TWindow::OrphanCallChain_C2_I39_0048d900(char param_1, char param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048d980
int TWindow::IsActionable() {
  if (field98 != 0 && g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0 && field08 != 0) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048d9c0
undefined TWindow::WrapperFor_SetWindowTextOrDelegateToOwner_At0048d9c0(undefined4* param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048d9f0
undefined TWindow::WrapperFor_FID_conflict_GetWindowTextA_At0048d9f0(undefined4 param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048da10
undefined TWindow::OrphanCallChain_C1_I08_0048da10() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048da40
void TWindow::SetField84(unsigned char param_1) {
  field84 = param_1;
}

// FUNCTION: IMPERIALISM 0x0048da60
undefined TWindow::ExecuteViewModalStateWithPushPopChain() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048dc60
undefined TWindow::OrphanCallChain_C1_I08_0048dc60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048dc90
undefined TWindow::OrphanCallChain_C2_I12_0048dc90(undefined4 param_1, undefined4 param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048dcc0
unsigned char* TWindow::GetEmbeddedDialogBehavior() {
  return &field74[0];
}

// FUNCTION: IMPERIALISM 0x0048dce0
void TWindow::AssertMcAppUILine2554() {
  if (g_McAppUiFlag_006A1B08 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0x9fa);
  }
}

// FUNCTION: IMPERIALISM 0x0048dd10
void TWindow::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x0048dd50
void TWindow::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x0048ddc0
undefined TWindow::OrphanCallChain_C2_I19_0048ddc0(TWindow* param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048de00
void TWindow::DispatchSlot9CToLinkedChildren() {}

// FUNCTION: IMPERIALISM 0x0048e060
void TWindow::CallVoidSlotA0() {}

// FUNCTION: IMPERIALISM 0x0048e120
undefined TWindow::OrphanCallChain_C2_I10_0048e120() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048e150
undefined TWindow::WrapperFor_CenterWindowWithinOwnerOrWorkArea_At0048e150(char param_1,
                                                                           char param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048e1c0
char TWindow::TestPointInBounds(CPoint* point) {
  return 3;
}

// FUNCTION: IMPERIALISM 0x0048e1e0
void TWindow::ReturnFromUiSlot60(int arg) {
  (void)arg;
  if (g_McAppUiFlag_006A1B10 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xac4);
  }
}

// FUNCTION: IMPERIALISM 0x0048e210
void TWindow::ReturnFromUiSlot61(int arg) {
  (void)arg;
  if (g_McAppUiFlag_006A1B14 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xad9);
  }
}

// FUNCTION: IMPERIALISM 0x0048e240
void TWindow::ReturnFromUiSlot62(int arg) {
  (void)arg;
  if (g_McAppUiFlag_006A1B18 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xaee);
  }
}

// FUNCTION: IMPERIALISM 0x0048e270
void TWindow::ReturnFromUiSlot63(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  if (g_McAppUiFlag_006A1B1C == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xaff);
  }
}

// FUNCTION: IMPERIALISM 0x0048e2a0
void TWindow::Free() {}

// FUNCTION: IMPERIALISM 0x00492cc0
class TView* TWindow::OwnerPanel() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00492ce0
class TView* TWindow::QueryOwnerContextPanel() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00492d00
void TWindow::TranslatePointToParentChain4E(int* point) {}

// FUNCTION: IMPERIALISM 0x00492d20
void TWindow::TranslatePointToParentChain4D(int* point) {}

// FUNCTION: IMPERIALISM 0x00492d40
void TWindow::DispatchVslot134WithRectAndRectPlus8_Impl(RECT* rect) {}

// FUNCTION: IMPERIALISM 0x00492d60
void TWindow::SubtractPosAndDispatchToOwnerSlot19C(int* point) {}

// FUNCTION: IMPERIALISM 0x00492d80
TObject* TWindow::ShallowClone() {
  AssertMcAppUiInvalidation(g_szMcAppUiHeaderPath_006943CC, 0x51e);
  return 0;
}
