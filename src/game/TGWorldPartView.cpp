#include "game/TGWorldPartView.h"

#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"

// SYNTHETIC: IMPERIALISM 0x0045b030
// TGWorldPartView::`scalar deleting destructor'
TGWorldPartView::~TGWorldPartView() {}
// SYNTHETIC: IMPERIALISM 0x004ac7d0
// TGWorldPartView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ac860
// TGWorldPartView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGWorldPartView, TView)

// FUNCTION: IMPERIALISM 0x0045b000
TGWorldPartView::TGWorldPartView() : TView() {
  sourceSurface60 = 0;
}

// FUNCTION: IMPERIALISM 0x004ac880
void TGWorldPartView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  if (sourceSurface60 != 0) {
    CRect destRect;
    QueryContentBounds(&destRect);
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(sourceSurface60->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &sourceRect64, &destRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x00577df0
void TGWorldPartView::SetSourceRectFromGridCell(int column, int row) {
  sourceRect64.left = column * frameWidth34;
  sourceRect64.top = row * frameHeight38;
  sourceRect64.right = (column + 1) * frameWidth34;
  sourceRect64.bottom = (row + 1) * frameHeight38;
}
