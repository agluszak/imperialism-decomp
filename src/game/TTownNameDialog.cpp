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
void TTownNameDialog::NoOpUiLifecycleHook(int arg) {}

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
