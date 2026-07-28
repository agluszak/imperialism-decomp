// UI wrapper class quads extracted from trade_screen.

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

// SYNTHETIC: IMPERIALISM 0x0058c1e0
// TNumberedArrowButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058c280
// TNumberedArrowButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNumberedArrowButton, TControl)

// FUNCTION: IMPERIALISM 0x0058c2a0
TNumberedArrowButton::TNumberedArrowButton() : TControl(), value84(0), value86(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058c2e0
// TNumberedArrowButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058c330
void TNumberedArrowButton::SetValue(short value84Arg, unsigned char refreshFlag) {
  value84 = value84Arg;
  if (refreshFlag != '\0') {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0058c360
void TNumberedArrowButton::SetState(short value86Arg, unsigned char refreshFlag) {
  CRect bounds;
  if (value86 != value86Arg) {
    if (refreshFlag != '\0') {
      RefreshControl();
      QueryBounds(&bounds);
    }
    value86 = value86Arg;
  }
}

// FUNCTION: IMPERIALISM 0x0058c3d0
void TNumberedArrowButton::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  UpdatePaletteIndexWithDefaultFallback(0x10);
  RECT srcRect;
  srcRect.left = (value86 != 2) ? 0xa : 0;
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0xb;
  srcRect.bottom = 0x10;
  RECT dstRect = {0, 0, 0xb, 0x10};
  TQuickDrawSurfaceContext* hintSource = g_pMacViewMgr->atlas694[4];
  BlitQuickDrawSurfaces(hintSource->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &dstRect,
                        0x24);
  srcRect.left = (value86 != 1) ? 0x21 : 0x16;
  srcRect.right = srcRect.left + 0xb;
  dstRect.top = 0x19;
  dstRect.bottom = 0x29;
  BlitQuickDrawSurfaces(hintSource->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &dstRect,
                        0x24);
  UpdatePaletteIndexWithDefaultFallback(0x13);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b67);
  SetQuickDrawTextOriginWithContextOffset(7, 0);
  RefreshControl();
}

// FUNCTION: IMPERIALISM 0x0058c640
void TNumberedArrowButton::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                      CPoint& currentPoint, unsigned char commandFlag) {
  (void)commandFlag;
  (void)startPoint;
  (void)previousPoint;
  short visualState = 0;
  if (PointInBoundsAndActionable(&currentPoint) != 0) {
    CRect bounds;
    BuildInsetContentRect(&bounds);
    short localY = static_cast<short>(currentPoint.y - bounds.top);
    if (localY > 0 && localY < frameHeight38 / 2) {
      visualState = 2;
    } else if (localY > frameHeight38 / 2 && localY < frameHeight38) {
      visualState = 1;
    }
  }
  if (phase >= kTrackPhaseBegin && phase < kTrackPhaseEnd) {
    if (value86 != visualState) {
      RefreshControl();
      CRect bounds;
      QueryBounds(&bounds);
      value86 = visualState;
    }
    PaintOrInvalidateControl(0);
    return;
  }
  if (phase == kTrackPhaseEnd && visualState != 0) {
    if (value86 != 0) {
      RefreshControl();
      CRect bounds;
      QueryBounds(&bounds);
      value86 = 0;
    }
    if (visualState == 2) {
      ownerContext->HandleEvent(100, this, 0);
    } else {
      ownerContext->HandleEvent(0x65, this, 0);
    }
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void TNumberedArrowButton::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* cursorPoint,
                                                                               RgnHandle hitArg) {
  if (IsActionable() != '\0') {
    if (cursorPoint->y < frameHeight38 / 2) {
      cursorId4e = 0x100;
      TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(cursorPoint, hitArg);
      return;
    }
    cursorId4e = (short)0xffff;
  }
  TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(cursorPoint, hitArg);
}
