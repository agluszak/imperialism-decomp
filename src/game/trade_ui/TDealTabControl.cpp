#include "game/trade_ui/TDealTabControl.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x00435540
// TDealTabControl::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00435570
TDealTabControl::~TDealTabControl() {}
// SYNTHETIC: IMPERIALISM 0x005bc690
// TDealTabControl::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bc760
// TDealTabControl::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealTabControl, TControl)

// NOOP: verified empty in original 0x005bc6c8 (no standalone TDealTabControl::TDealTabControl body exists: CreateObject 0x005bc690 inlines this default ctor, calling the TControl base ctor directly at that site)
TDealTabControl::TDealTabControl() {}

// FUNCTION: IMPERIALISM 0x005bc780
void TDealTabControl::Setup(short bitmapResourceId, unsigned char useAlternatePair) {
  if (useAlternatePair) {
    ++bitmapResourceId;
  } else {
    tabCount88 = 15;
  }
  filledRowStrip8c = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(bitmapResourceId);
  emptyRowStrip90 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(bitmapResourceId + 4);
  rowHeightPx86 = 25;
}

// Vertical 3-segment fill bar: empty strip above the highlight band, the filled strip
// for exactly one row's height at the selected row, empty strip below (only drawn if
// there's room left). No selection (selectedRow84 < 0) draws the whole area empty.
// FUNCTION: IMPERIALISM 0x005bc7f0
void TDealTabControl::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
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
void TDealTabControl::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                 CPoint& currentPoint, unsigned char commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;

  short hoveredRow = -1;
  if (PointInBoundsAndActionable(&currentPoint) != 0) {
    CRect contentRect;
    BuildInsetContentRect(&contentRect);
    hoveredRow = static_cast<short>(static_cast<short>(currentPoint.y) -
                                    static_cast<short>(contentRect.top)) /
                 rowHeightPx86;
    if (hoveredRow < tabCount88) {
      if (hoveredRow != selectedRow84) {
        selectedRow84 = hoveredRow;
      }
    } else {
      hoveredRow = selectedRow84;
    }
  }

  if (phase >= kTrackPhaseBegin && phase <= kTrackPhaseUpdate) {
    if (hoveredRow != -1) {
      PaintOrInvalidateControl(0);
    }
    return;
  }
  if (phase == kTrackPhaseEnd) {
    if (PointInBoundsAndActionable(&currentPoint) != 0) {
      ownerContext->HandleEvent(selectedRow84 + 11000, this, 0);
      PaintOrInvalidateControl(0);
      return;
    }
    selectedRow84 = -1;
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x005bcb20
void TDealTabControl::Free() {
  if (filledRowStrip8c != 0) {
    g_pDisplayMgr->RemoveGWorld(filledRowStrip8c);
  }
  if (emptyRowStrip90 != 0) {
    g_pDisplayMgr->RemoveGWorld(emptyRowStrip90);
  }
  TView::Free();
}
