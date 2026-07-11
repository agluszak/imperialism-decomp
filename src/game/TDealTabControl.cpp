#include "game/TDealTabControl.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x00435540
// TDealTabControl::`scalar deleting destructor'
TDealTabControl::~TDealTabControl() {}
// SYNTHETIC: IMPERIALISM 0x005bc690
// TDealTabControl::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bc760
// TDealTabControl::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealTabControl, TControl)

TDealTabControl::TDealTabControl() {}

// FUNCTION: IMPERIALISM 0x005bc780
undefined TDealTabControl::ConstructTDealTabControlBaseState() {
  return 0;
}

// Vertical 3-segment fill bar: empty strip above the highlight band, the filled strip
// for exactly one row's height at the selected row, empty strip below (only drawn if
// there's room left). No selection (selectedRow84 < 0) draws the whole area empty.
// FUNCTION: IMPERIALISM 0x005bc7f0
void TDealTabControl::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  if (filledRowStrip8c == nullptr) {
    return;
  }
  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);
  SetQuickDrawFillColor(0);

  if (selectedRow84 < 0) {
    RECT rect = {0, 0, frameWidth34, frameHeight38};
    BlitRectWithOptionalTransparency(emptyRowStrip90->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &rect,
                                     &rect, 0, 0);
    return;
  }

  int bandTop = selectedRow84 * rowHeightPx86;
  if (bandTop != 0) {
    RECT rect = {0, 0, frameWidth34, bandTop};
    BlitRectWithOptionalTransparency(emptyRowStrip90->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &rect,
                                     &rect, 0, 0);
  }

  int bandBottom = bandTop + rowHeightPx86;
  RECT bandRect = {0, bandTop, frameWidth34, bandBottom};
  BlitRectWithOptionalTransparency(filledRowStrip8c->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bandRect,
                                   &bandRect, 0, 0);

  if (bandBottom < frameHeight38) {
    RECT rect = {0, bandBottom, frameWidth34, frameHeight38};
    BlitRectWithOptionalTransparency(emptyRowStrip90->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &rect,
                                     &rect, 0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x005bc9f0
void TDealTabControl::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                     void* pEventDataA, void* pEventDataB,
                                                     int nCommandFlag) {
  (void)nCommandFlag;
}

// FUNCTION: IMPERIALISM 0x005bcb20
void TDealTabControl::Free() {}
