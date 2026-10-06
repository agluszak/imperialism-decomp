#include "game/app/TGWorldPartView.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"

// FUNCTION: IMPERIALISM 0x0045b000
TGWorldPartView::TGWorldPartView() : TView() {
  sourceSurface = 0;
}

// FUNCTION: IMPERIALISM 0x0045b060
TGWorldPartView::~TGWorldPartView() {}

IMPLEMENT_DYNCREATE(TGWorldPartView, TView)

// FUNCTION: IMPERIALISM 0x004ac3a0
CString AssignSharedStringFromMidSubstring(CString source, int startPos, int count) {
  return source.Mid(startPos - 1, count);
}

// FUNCTION: IMPERIALISM 0x004ac880
void TGWorldPartView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  if (sourceSurface != 0) {
    CRect destRect;
    QueryContentBounds(&destRect);
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(sourceSurface->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect, &destRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x00577df0
void TGWorldPartView::SetSourceRectFromGridCell(int column, int row) {
  sourceRect.left = column * frameWidth;
  sourceRect.top = row * frameHeight;
  sourceRect.right = (column + 1) * frameWidth;
  sourceRect.bottom = (row + 1) * frameHeight;
}
