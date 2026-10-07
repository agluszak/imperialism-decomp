#include "game/map_ui/TTownNameDialog.h"
#include "game/ui_tags_common.h"

#include "game/ui_core/TEditText.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/map_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"

#include <stdlib.h>

IMPLEMENT_DYNCREATE(TTownNameDialog, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0051bb10
TTownNameDialog::TTownNameDialog() : TNoHilitePicture() {}

// FUNCTION: IMPERIALISM 0x0051bb70
TTownNameDialog::~TTownNameDialog() {}

// FUNCTION: IMPERIALISM 0x0051bb90
void TTownNameDialog::DoPostCreate(int arg) {
  CString text;

  TView::DoPostCreate(arg);

  TEditText* nameControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagName));
  if (nameControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUMapDlog, 0x4d3);
  }

  // LIBRARY: rand (0x005e83f0)
  short suggestedNameIndex = static_cast<short>(rand() % 8 + 1);
  nameControl->SetTextWithStrListID(0x1c52, suggestedNameIndex, true);
  UpdatePaletteIndexWithDefaultFallback(0x50);
  nameControl->BecomeTarget();
  nameControl->GetCurrentText(&text);
  nameControl->SetEditSelectionAndScrollCaret(0, static_cast<short>(text.GetLength()), 1);
}

// FUNCTION: IMPERIALISM 0x0051bcc0
void TTownNameDialog::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  TView* nameControl = ResolveControlByTag(kControlTagName);
  if (nameControl != NULL) {
    CRect bounds;
    nameControl->QueryBounds(&bounds);
    g_pViewMgr->SetForeColor(0xf);
    FillRectWithQuickDrawBrushAndContextOffset(&bounds);
  }
  UpdatePaletteIndexWithDefaultFallback(0x50);
}
