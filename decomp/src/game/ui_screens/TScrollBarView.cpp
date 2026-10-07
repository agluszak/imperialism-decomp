#include "game/ui_screens/TScrollBarView.h"
#include "game/ui_tags_screens.h"

#include "game/gfx/CDib.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_screens/TPictureButton.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TScrollView.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x00573e20
TScrollBarView::~TScrollBarView() {}

// FUNCTION: IMPERIALISM 0x005740a0
void TScrollBarView::RefreshCityDialogScrollableViewportWithQuickDrawContext() {
  ScopedMapQuickDrawContext quickDrawContext(this);
  PrepareForDrawing();
  RECT rect = {0, minValue, frameWidth, static_cast<int>(maxValue) + 0x12};
  Draw(&rect);
}

IMPLEMENT_DYNCREATE(TScrollBarView, TControl)

// FUNCTION: IMPERIALISM 0x005744b0
void TScrollBarView::IScrollBarView(TScrollView* panel, int* offsetLayout, int* sizeLayout) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  ownerView = static_cast<TScrollView*>(ownerContext);
  ownerView->AssertValid();
  minValue = 0x12;
  maxValue = static_cast<short>(frameHeight) - 0x24;
  currentValue = 0x12;

  {
    RECT surfaceRect;
    surfaceRect.left = 0;
    surfaceRect.top = 0;
    surfaceRect.right = frameWidth;
    surfaceRect.bottom = frameHeight;
    g_pDisplayMgr->MakeNewGWorld(surfaceContext, 8, surfaceRect);
  }

  TPictureButton* upButton = new TPictureButton();
  {
    int buttonSize[2];
    int buttonOffset[2];
    buttonSize[0] = 0x12;
    buttonSize[1] = 0x12;
    buttonOffset[0] = 3;
    buttonOffset[1] = 0;
    upButton->IPicture(this, buttonOffset, buttonSize, 5, 5, 0xbbb);
  }
  upButton->controlTag = kControlTagScup; // 'scup'
  upButton->Show(0, 1);
  upButton->ViewEnable(1, 0);

  TPictureButton* downButton = new TPictureButton();
  {
    int buttonOffset[2];
    int buttonSize[2];
    buttonOffset[0] = 3;
    buttonOffset[1] = frameHeight - 0x12;
    buttonSize[0] = 0x12;
    buttonSize[1] = 0x12;
    downButton->IPicture(this, buttonOffset, buttonSize, 5, 5, 0xbbc);
  }
  downButton->controlTag = kControlTagScdn; // 'scdn'
  downButton->Show(0, 1);
  downButton->ViewEnable(1, 0);
}

// FUNCTION: IMPERIALISM 0x005746e0
void TScrollBarView::Free() {
  if (surfaceContext != 0) {
    g_pDisplayMgr->RemoveGWorld(surfaceContext);
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00574720
void TScrollBarView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  ownerView = static_cast<TScrollView*>(ownerContext);
  ownerView->AssertValid();
  minValue = 0x12;
  currentValue = 0x12;

  RECT surfaceRect;
  surfaceRect.left = 0;
  surfaceRect.top = 0;
  surfaceRect.bottom = frameHeight;
  maxValue = static_cast<short>(frameHeight) - 0x24;
  surfaceRect.right = frameWidth;
  g_pDisplayMgr->MakeNewGWorld(surfaceContext, 8, surfaceRect);
}

// FUNCTION: IMPERIALISM 0x005747c0
void TScrollBarView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    if (sourceHandler->controlTag == kControlTagScup) { // 'scup'
      ownerView->ScrollRelative(0, 0xc);
    } else if (sourceHandler->controlTag == kControlTagScdn) { // 'scdn'
      ownerView->ScrollRelative(0, -0xc);
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00574830
void TScrollBarView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  RECT thumbRect = {0, currentValue, frameWidth, static_cast<int>(currentValue) + 0x12};
  if (PtInRect(&thumbRect, point)) {
    TControl::DoMouseCommand(point, event, origin);
    return;
  }

  int y = point.y;
  if (y >= minValue && y < currentValue) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58);
    ownerView->ScrollRelative(0, static_cast<short>(ownerView->frameHeight));
    return;
  }

  if (y > maxValue + 0x12 || y <= currentValue + 0x12) {
    return;
  }
  g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58);
  ownerView->ScrollRelative(0, -static_cast<short>(ownerView->frameHeight));
}

// FUNCTION: IMPERIALISM 0x00574970
void TScrollBarView::Draw(RECT* rectBuffer) {
  ResetQuickDrawStrokeState();
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  RECT srcRect;
  RECT dstRect;
  srcRect.bottom = currentValue;
  srcRect.right = frameWidth;
  srcRect.left = 0;
  dstRect.left = 0;
  srcRect.top = 0;
  dstRect.top = 0;
  dstRect.right = srcRect.right;
  dstRect.bottom = srcRect.bottom;
  if (g_pMacViewMgr->tileOverlayStripWorlds[5]->blitSurface.surfaceDib != NULL) {
    int h = g_pMacViewMgr->tileOverlayStripWorlds[5]->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&srcRect, 0, (h - srcRect.top) - srcRect.bottom);
  }
  if (surfaceContext->blitSurface.surfaceDib != NULL) {
    int h = surfaceContext->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&dstRect, 0, (h - dstRect.top) - dstRect.bottom);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[5]->GetBlitSurface(),
                                   surfaceContext->GetBlitSurface(), &srcRect, &dstRect, 0, NULL);

  srcRect.right = frameWidth;
  srcRect.left = 0;
  dstRect.top = currentValue;
  srcRect.top = 0x12c;
  srcRect.bottom = 0x13e;
  dstRect.left = 0;
  dstRect.bottom = dstRect.top + 0x12;
  dstRect.right = srcRect.right;
  if (g_pMacViewMgr->tileOverlayStripWorlds[5]->blitSurface.surfaceDib != NULL) {
    int h = g_pMacViewMgr->tileOverlayStripWorlds[5]->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&srcRect, 0, h - 0x26a);
  }
  if (surfaceContext->blitSurface.surfaceDib != NULL) {
    int h = surfaceContext->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&dstRect, 0, (h - dstRect.top) - dstRect.bottom);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[5]->GetBlitSurface(),
                                   surfaceContext->GetBlitSurface(), &srcRect, &dstRect, 0, NULL);

  dstRect.top = currentValue + 0x12;
  srcRect.top = 299 - static_cast<short>(static_cast<short>(frameHeight) - currentValue - 0x12);
  srcRect.right = frameWidth;
  srcRect.bottom = 300;
  dstRect.bottom = frameHeight;
  srcRect.left = 0;
  dstRect.left = 0;
  dstRect.right = srcRect.right;
  if (g_pMacViewMgr->tileOverlayStripWorlds[5]->blitSurface.surfaceDib != NULL) {
    int h = g_pMacViewMgr->tileOverlayStripWorlds[5]->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&srcRect, 0, (h - srcRect.top) - 300);
  }
  if (surfaceContext->blitSurface.surfaceDib != NULL) {
    int h = surfaceContext->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&dstRect, 0, (h - dstRect.top) - dstRect.bottom);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->tileOverlayStripWorlds[5]->GetBlitSurface(),
                                   surfaceContext->GetBlitSurface(), &srcRect, &dstRect, 0, NULL);

  srcRect = *rectBuffer;
  BlitRectWithOptionalTransparency(surfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &srcRect, 0, NULL);
}

// FUNCTION: IMPERIALISM 0x00574d10
void TScrollBarView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, bool commandFlag) {
  short target = static_cast<short>(currentPoint.y) - 9;
  if (phase <= kTrackPhaseBegin || phase > kTrackPhaseEnd) {
    return;
  }

  if (target > maxValue) {
    target = maxValue;
  } else if (target < minValue) {
    target = minValue;
  }
  if (target != currentValue) {
    currentValue = target;
    RefreshCityDialogScrollableViewportWithQuickDrawContext();
  }

  if (phase != kTrackPhaseEnd) {
    return;
  }

  int ratio = (currentValue - minValue) * 1024 / (maxValue - minValue);
  TView* content = ownerView->contentView;
  if (content == NULL) {
    return;
  }
  short heightDiff =
      static_cast<short>(content->frameHeight) - static_cast<short>(ownerView->frameHeight);
  if (heightDiff <= 0) {
    return;
  }
  CPoint origin;
  origin.y = -(ratio * heightDiff / 1024);
  origin.x = content->ownerLocalX;
  content->Locate(origin, true);
}

// FUNCTION: IMPERIALISM 0x00574e20
void TScrollBarView::SetThumb(int percent, unsigned char refresh) {
  short value = static_cast<short>(
      minValue +
      ((maxValue - minValue) * percent + ((maxValue - minValue) * percent >> 31 & 0x3ff)) / 1024);
  currentValue = value;
  if (currentValue < minValue) {
    currentValue = minValue;
  } else if (currentValue > maxValue) {
    currentValue = maxValue;
  }
  if (refresh != 0) {
    RefreshCityDialogScrollableViewportWithQuickDrawContext();
  }
}
