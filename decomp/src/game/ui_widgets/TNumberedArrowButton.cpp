#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/ui_text_label_helpers_decls.h"
#include <new>

IMPLEMENT_DYNCREATE(TNumberedArrowButton, TControl)

// FUNCTION: IMPERIALISM 0x0058c2a0
TNumberedArrowButton::TNumberedArrowButton() : number(0), arrowState(0) {}

// FUNCTION: IMPERIALISM 0x0058c330
void TNumberedArrowButton::SetValue(short value84Arg, bool refreshFlag) {
  number = value84Arg;
  if (refreshFlag != '\0') {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0058c360
void TNumberedArrowButton::SetState(short value86Arg, unsigned char refreshFlag) {
  CRect bounds;
  if (arrowState != value86Arg) {
    if (refreshFlag != '\0') {
      RefreshControl();
      GetFrame(&bounds);
    }
    arrowState = value86Arg;
  }
}

// FUNCTION: IMPERIALISM 0x0058c3d0
void TNumberedArrowButton::Draw(RECT* rectBuffer) {
  UpdatePaletteIndexWithDefaultFallback(0x10);
  RECT srcRect;
  srcRect.left = (arrowState != 2) ? 0xa : 0;
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0xb;
  srcRect.bottom = 0x10;
  RECT dstRect = {0, 0, 0xb, 0x10};
  TQuickDrawSurfaceContext* hintSource = g_pMacViewMgr->tileOverlayStripWorlds[4];
  BlitRectWithOptionalTransparency(hintSource->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24);
  srcRect.left = (arrowState != 1) ? 0x21 : 0x16;
  srcRect.right = srcRect.left + 0xb;
  dstRect.top = 0x19;
  dstRect.bottom = 0x29;
  BlitRectWithOptionalTransparency(hintSource->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24);
  UpdatePaletteIndexWithDefaultFallback(0x13);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b67);
  SetQuickDrawTextOriginWithContextOffset(7, 0);
  RefreshControl();
}

// FUNCTION: IMPERIALISM 0x0058c640
void TNumberedArrowButton::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                      CPoint& currentPoint, bool commandFlag) {
  short visualState = 0;
  if (PointInBoundsAndActionable(&currentPoint) != 0) {
    CRect bounds;
    BuildInsetContentRect(&bounds);
    short localY = currentPoint.y - bounds.top;
    if (localY > 0 && localY < frameHeight / 2) {
      visualState = 2;
    } else if (localY > frameHeight / 2 && localY < frameHeight) {
      visualState = 1;
    }
  }
  if (phase < kTrackPhaseBegin) {
    return;
  }
  if (phase > kTrackPhaseUpdate) {
    if (phase != kTrackPhaseEnd || visualState == 0) {
      return;
    }
    if (arrowState != 0) {
      RefreshControl();
      CRect bounds;
      GetFrame(&bounds);
      arrowState = 0;
    }
    if (visualState == 2) {
      ownerContext->HandleEvent(100, this, 0);
      PaintOrInvalidateControl(0);
      return;
    }
    ownerContext->HandleEvent(0x65, this, 0);
    PaintOrInvalidateControl(0);
    return;
  } else {
    if (arrowState != visualState) {
      RefreshControl();
      CRect bounds;
      GetFrame(&bounds);
      arrowState = visualState;
    }
    PaintOrInvalidateControl(0);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void TNumberedArrowButton::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* cursorPoint,
                                                                               RgnHandle hitArg) {
  if (IsActionable() != '\0') {
    if (cursorPoint->y < frameHeight / 2) {
      cursorId = 0x100;
      TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(cursorPoint, hitArg);
      return;
    }
    cursorId = static_cast<short>(0xffff);
  }
  TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(cursorPoint, hitArg);
}
