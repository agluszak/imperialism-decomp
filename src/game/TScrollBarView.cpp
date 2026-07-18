#include "game/TScrollBarView.h"

#include "game/ScopedMapQuickDrawContext.h"
#include "game/TDisplayMgr.h"
#include "game/TPictureButton.h"
#include "game/TScrollView.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00573df0
// TScrollBarView::`scalar deleting destructor'
TScrollBarView::~TScrollBarView() {}

// FUNCTION: IMPERIALISM 0x005740a0
void TScrollBarView::RefreshCityDialogScrollableViewportWithQuickDrawContext() {
  ScopedMapQuickDrawContext quickDrawContext(this);
  Refresh();
  RECT rect = {0, word88, frameWidth34, static_cast<int>(word8a) + 0x12};
  ApplyRectSlot110(&rect);
}
// SYNTHETIC: IMPERIALISM 0x005743f0
// TScrollBarView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00574490
// TScrollBarView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScrollBarView, TControl)

// This address was previously claimed by a fabricated empty `TScrollBarView()` body;
// the real ctor is inline (see the header) and 0x5744b0 is the 3-arg builder below.
// FUNCTION: IMPERIALISM 0x005744b0
void TScrollBarView::ConstructTScrollBarViewBaseState(TScrollView* panel, int* offsetLayout,
                                                      int* sizeLayout) {
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
    g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&surfaceContext90, 8, &surfaceRect);
  }

  TPictureButton* upButton = new TPictureButton();
  {
    int buttonSize[2];
    int buttonOffset[2];
    buttonSize[0] = 0x12;
    buttonSize[1] = 0x12;
    buttonOffset[0] = 3;
    buttonOffset[1] = 0;
    upButton->InitializePictureEntryBaseAndRefresh(this, buttonOffset, buttonSize, 5, 5, 0xbbb);
  }
  upButton->controlTag = 0x73637570; // 'scup'
  upButton->SetEnabled(0, 1);
  upButton->SetState(1, 0);

  TPictureButton* downButton = new TPictureButton();
  {
    int buttonOffset[2];
    int buttonSize[2];
    buttonOffset[0] = 3;
    buttonOffset[1] = frameHeight38 - 0x12;
    buttonSize[0] = 0x12;
    buttonSize[1] = 0x12;
    downButton->InitializePictureEntryBaseAndRefresh(this, buttonOffset, buttonSize, 5, 5, 0xbbc);
  }
  downButton->controlTag = 0x7363646e; // 'scdn'
  downButton->SetEnabled(0, 1);
  downButton->SetState(1, 0);
}

// FUNCTION: IMPERIALISM 0x005746e0
void TScrollBarView::Free() {
  if (surfaceContext90 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&surfaceContext90);
  }
  TView::Free();
}

// Not a no-op despite the inherited slot name: re-cache+assert the owner, re-seed the
// bounded-value words, and re-allocate the 8-bit surface for the current frame rect.
// FUNCTION: IMPERIALISM 0x00574720
void TScrollBarView::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
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
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&surfaceContext90, 8, &surfaceRect);
}

// FUNCTION: IMPERIALISM 0x005747c0
void TScrollBarView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    if (sourceHandler->controlTag == 0x73637570) { // 'scup'
      ownerView84->AdjustCityDialogScrollRangeByDeltaAndClamp(0, 0xc);
    } else if (sourceHandler->controlTag == 0x7363646e) { // 'scdn'
      ownerView84->AdjustCityDialogScrollRangeByDeltaAndClamp(0, -0xc);
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00574830
void TScrollBarView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                          int arg4) {
  RECT thumbRect = {0, word8c, frameWidth34, static_cast<int>(word8c) + 0x12};
  if (PtInRect(&thumbRect, *point)) {
    TControl::BeginMouseCaptureAndStartRepeatTimer(point, 0, 0, 0);
    return;
  }

  int y = point->y;
  if (y >= word88 && y < word8c) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58);
    ownerView84->AdjustCityDialogScrollRangeByDeltaAndClamp(
        0, static_cast<short>(ownerView84->frameHeight38));
    return;
  }

  if (y > word8a + 0x12 || y <= word8c + 0x12) {
    return;
  }
  g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58);
  ownerView84->AdjustCityDialogScrollRangeByDeltaAndClamp(
      0, -static_cast<short>(ownerView84->frameHeight38));
}

// FUNCTION: IMPERIALISM 0x00574970
void TScrollBarView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00574d10
void TScrollBarView::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                    void* pEventDataA, void* pEventDataB,
                                                    int nCommandFlag) {
  (void)nCommandFlag;
}
