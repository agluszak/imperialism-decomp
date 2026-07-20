#include "game/TTownNameDialog.h"

#include "game/TPicture.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x0051ba70
// TTownNameDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0051baf0
// TTownNameDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTownNameDialog, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0051bb10
TTownNameDialog::TTownNameDialog() : TNoHilitePicture() {}

// SYNTHETIC: IMPERIALISM 0x0051bb40
// TTownNameDialog::`scalar deleting destructor'
TTownNameDialog::~TTownNameDialog() {}

// FUNCTION: IMPERIALISM 0x0051bb90
void TTownNameDialog::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

  TView* nameControl = ResolveControlByTag(kControlTagName);
  // TODO: the original null-checks nameControl (MessageBoxA + abort on failure, standard
  // g_szUiNilPointerMessage/g_szUiFailureMessage pattern used elsewhere), rolls a random
  // suggested-name index (rand() % 8 + 1), then calls FOUR methods on it through vtable
  // slots 0x1cc, 0x7c, 0x1dc, 0x1d8. Confirmed NOT TStaticText-compatible at slot 0x1cc:
  // TStaticText::LoadUiStringAndDispatchViaVslot1C8 takes 3 args (group, index, refresh),
  // but this callsite (0x51bc1a-0x51bc1f) only pushes 2 (group=0x1c52, index=randVal) --
  // a real arity mismatch, not just an unresolved refresh flag. nameControl's concrete
  // class needs identifying (no direct `new`/RegisterUiResourceEntry construction site
  // found yet tying a specific control class to this dialog's 'name' tag) before these
  // four calls can be modeled without guessing a type, per the type-modeling guardrail.
  (void)nameControl;
}

// FUNCTION: IMPERIALISM 0x0051bcc0
void TTownNameDialog::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
  TView* nameControl = ResolveControlByTag(kControlTagName);
  if (nameControl != nullptr) {
    RECT bounds;
    nameControl->QueryBounds(&bounds);
    g_pUiRuntimeContext->ApplyLegendSplitSlot34(0xf);
    FillRectWithQuickDrawBrushAndContextOffset(&bounds);
  }
  UpdatePaletteIndexWithDefaultFallback(0x50);
}
