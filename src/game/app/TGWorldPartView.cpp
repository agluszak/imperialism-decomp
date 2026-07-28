#include "game/app/TGWorldPartView.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"

// FUNCTION: IMPERIALISM 0x0045b000
TGWorldPartView::TGWorldPartView() : TView() {
  sourceSurface60 = 0;
}

// SYNTHETIC: IMPERIALISM 0x0045b030
// TGWorldPartView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0045b060
TGWorldPartView::~TGWorldPartView() {}
// SYNTHETIC: IMPERIALISM 0x004ac7d0
// TGWorldPartView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ac860
// TGWorldPartView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGWorldPartView, TView)

// One-based CString::Mid: returns source.Mid(startPos - 1, count). Both original call
// sites (0x4aaf59 in TMiniArmyView::Draw and 0x5d4cbe in
// TruncateTextToFitWidthWithEllipsis) pass startPos = 1 and count = GetLength() - 1,
// i.e. "drop the last character", which is the step those truncation loops repeat.
//
// Receiver caveat (imperialism-decomp-1uj.98.4): the original is __thiscall with ECX
// holding a plain CString* -- 0x5d4cb5 loads CStringData::nDataLength from
// [m_pchData - 8] on the very object it then passes in ECX -- and takes (dest, start,
// count) on the stack, RET 0xc. There is no game class to own it (no CString-derived
// type exists) and CString itself is MFC, which we do not model, so the receiver is
// expressed as an ordinary parameter here rather than faked with a calling-convention
// cast. That costs the out-of-line match but keeps the source model honest; both
// callers currently inline the Mid instead of calling this helper.
// FUNCTION: IMPERIALISM 0x004ac3a0
CString AssignSharedStringFromMidSubstring(CString source, int startPos, int count) {
  return source.Mid(startPos - 1, count);
}

// FUNCTION: IMPERIALISM 0x004ac880
void TGWorldPartView::Draw(RECT* rectBuffer) {
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
