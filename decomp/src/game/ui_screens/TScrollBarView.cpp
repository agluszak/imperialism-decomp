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

// SYNTHETIC: IMPERIALISM 0x00573df0
// TScrollBarView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00573e20
TScrollBarView::~TScrollBarView() {}

// FUNCTION: IMPERIALISM 0x005740a0
void TScrollBarView::RefreshCityDialogScrollableViewportWithQuickDrawContext() {
  ScopedMapQuickDrawContext quickDrawContext(this);
  PrepareForDrawing();
  RECT rect = {0, word88, frameWidth34, static_cast<int>(word8a) + 0x12};
  Draw(&rect);
}

// SYNTHETIC: IMPERIALISM 0x005743f0
// TScrollBarView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00574490
// TScrollBarView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScrollBarView, TControl)

// This address was previously claimed by a fabricated empty `TScrollBarView()` body;
// the real ctor is inline (see the header) and 0x5744b0 is the 3-arg builder below.
// FUNCTION: IMPERIALISM 0x005744b0
void TScrollBarView::InitializeScrollBar(TScrollView* panel, int* offsetLayout, int* sizeLayout) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  ownerView84 = static_cast<TScrollView*>(ownerContext);
  ownerView84->AssertValid();
  word88 = 0x12;
  word8a = static_cast<short>(frameHeight38) - 0x24;
  word8c = 0x12;

  {
    RECT surfaceRect;
    surfaceRect.left = 0;
    surfaceRect.top = 0;
    surfaceRect.right = frameWidth34;
    surfaceRect.bottom = frameHeight38;
    g_pDisplayMgr->MakeNewGWorld(surfaceContext90, 8, surfaceRect);
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
    buttonOffset[1] = frameHeight38 - 0x12;
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
  if (surfaceContext90 != 0) {
    g_pDisplayMgr->RemoveGWorld(surfaceContext90);
  }
  TView::Free();
}

// Not a no-op despite the inherited slot name: re-cache+assert the owner, re-seed the
// bounded-value words, and re-allocate the 8-bit surface for the current frame rect.
// FUNCTION: IMPERIALISM 0x00574720
void TScrollBarView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  ownerView84 = static_cast<TScrollView*>(ownerContext);
  ownerView84->AssertValid();
  word88 = 0x12;
  word8c = 0x12;

  RECT surfaceRect;
  surfaceRect.left = 0;
  surfaceRect.top = 0;
  surfaceRect.bottom = frameHeight38;
  word8a = static_cast<short>(frameHeight38) - 0x24;
  surfaceRect.right = frameWidth34;
  g_pDisplayMgr->MakeNewGWorld(surfaceContext90, 8, surfaceRect);
}

// FUNCTION: IMPERIALISM 0x005747c0
void TScrollBarView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    if (sourceHandler->controlTag == kControlTagScup) { // 'scup'
      ownerView84->ScrollRelative(0, 0xc);
    } else if (sourceHandler->controlTag == kControlTagScdn) { // 'scdn'
      ownerView84->ScrollRelative(0, -0xc);
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00574830
void TScrollBarView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  RECT thumbRect = {0, word8c, frameWidth34, static_cast<int>(word8c) + 0x12};
  if (PtInRect(&thumbRect, point)) {
    TControl::DoMouseCommand(point, event, origin);
    return;
  }

  int y = point.y;
  if (y >= word88 && y < word8c) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58);
    ownerView84->ScrollRelative(0, static_cast<short>(ownerView84->frameHeight38));
    return;
  }

  if (y > word8a + 0x12 || y <= word8c + 0x12) {
    return;
  }
  g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58);
  ownerView84->ScrollRelative(0, -static_cast<short>(ownerView84->frameHeight38));
}

// FUNCTION: IMPERIALISM 0x00574970
void TScrollBarView::Draw(RECT* rectBuffer) {
  ResetQuickDrawStrokeState();
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  RECT srcRect;
  RECT dstRect;
  srcRect.bottom = word8c;
  srcRect.right = frameWidth34;
  srcRect.left = 0;
  dstRect.left = 0;
  srcRect.top = 0;
  dstRect.top = 0;
  dstRect.right = srcRect.right;
  dstRect.bottom = srcRect.bottom;
  if (g_pMacViewMgr->atlas694[5]->blitSurface.surfaceDib != nullptr) {
    int h = g_pMacViewMgr->atlas694[5]->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&srcRect, 0, (h - srcRect.top) - srcRect.bottom);
  }
  if (surfaceContext90->blitSurface.surfaceDib != nullptr) {
    int h = surfaceContext90->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&dstRect, 0, (h - dstRect.top) - dstRect.bottom);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[5]->GetBlitSurface(),
                                   surfaceContext90->GetBlitSurface(), &srcRect, &dstRect, 0,
                                   nullptr);

  srcRect.right = frameWidth34;
  srcRect.left = 0;
  dstRect.top = word8c;
  srcRect.top = 0x12c;
  srcRect.bottom = 0x13e;
  dstRect.left = 0;
  dstRect.bottom = dstRect.top + 0x12;
  dstRect.right = srcRect.right;
  if (g_pMacViewMgr->atlas694[5]->blitSurface.surfaceDib != nullptr) {
    int h = g_pMacViewMgr->atlas694[5]->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&srcRect, 0, h - 0x26a);
  }
  if (surfaceContext90->blitSurface.surfaceDib != nullptr) {
    int h = surfaceContext90->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&dstRect, 0, (h - dstRect.top) - dstRect.bottom);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[5]->GetBlitSurface(),
                                   surfaceContext90->GetBlitSurface(), &srcRect, &dstRect, 0,
                                   nullptr);

  dstRect.top = word8c + 0x12;
  srcRect.top = 299 - static_cast<short>(static_cast<short>(frameHeight38) - word8c - 0x12);
  srcRect.right = frameWidth34;
  srcRect.bottom = 300;
  dstRect.bottom = frameHeight38;
  srcRect.left = 0;
  dstRect.left = 0;
  dstRect.right = srcRect.right;
  if (g_pMacViewMgr->atlas694[5]->blitSurface.surfaceDib != nullptr) {
    int h = g_pMacViewMgr->atlas694[5]->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&srcRect, 0, (h - srcRect.top) - 300);
  }
  if (surfaceContext90->blitSurface.surfaceDib != nullptr) {
    int h = surfaceContext90->blitSurface.surfaceDib->GetAbsoluteHeight();
    OffsetRect(&dstRect, 0, (h - dstRect.top) - dstRect.bottom);
  }
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas694[5]->GetBlitSurface(),
                                   surfaceContext90->GetBlitSurface(), &srcRect, &dstRect, 0,
                                   nullptr);

  srcRect = *rectBuffer;
  BlitRectWithOptionalTransparency(surfaceContext90->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &srcRect, 0, nullptr);
}

// FUNCTION: IMPERIALISM 0x00574d10
void TScrollBarView::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                                CPoint& currentPoint, unsigned char commandFlag) {
  (void)startPoint;
  (void)previousPoint;
  (void)commandFlag;
  short target = static_cast<short>(currentPoint.y) - 9;
  if (phase <= kTrackPhaseBegin || phase > kTrackPhaseEnd) {
    return;
  }

  if (target > word8a) {
    target = word8a;
  } else if (target < word88) {
    target = word88;
  }
  if (target != word8c) {
    word8c = target;
    RefreshCityDialogScrollableViewportWithQuickDrawContext();
  }

  if (phase != kTrackPhaseEnd) {
    return;
  }

  int ratio = (word8c - word88) * 1024 / (word8a - word88);
  TView* content = ownerView84->contentView60;
  if (content == nullptr) {
    return;
  }
  short heightDiff =
      static_cast<short>(content->frameHeight38) - static_cast<short>(ownerView84->frameHeight38);
  if (heightDiff <= 0) {
    return;
  }
  CPoint origin;
  origin.y = -(ratio * heightDiff / 1024);
  origin.x = content->ownerLocalX;
  content->Locate(origin, 1);
}
// FUNCTION: IMPERIALISM 0x00574e20
void TScrollBarView::SetThumb(int percent, unsigned char refresh) {
  short value = static_cast<short>(
      word88 + ((word8a - word88) * percent + ((word8a - word88) * percent >> 31 & 0x3ff)) / 0x400);
  word8c = value;
  if (word8c < word88) {
    word8c = word88;
  } else if (word8c > word8a) {
    word8c = word8a;
  }
  if (refresh != 0) {
    RefreshCityDialogScrollableViewportWithQuickDrawContext();
  }
}
