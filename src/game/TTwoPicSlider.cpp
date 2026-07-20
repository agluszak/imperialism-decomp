// TTwoPicSlider draw/input vertical slice.

#include "decomp_types.h"
#include "game/TTwoPicSlider.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/TDisplayMgr.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include <new>
#include "game/CString.h"

// SYNTHETIC: IMPERIALISM 0x0056e120
// TTwoPicSlider::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056e1e0
// TTwoPicSlider::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTwoPicSlider, TControl)

// Constructor body is inlined into the CreateObject factory in the original binary
// (0x0056e120): allocate, run the base TControl ctor, patch the vtable, zero the
// slider-specific fields.
TTwoPicSlider::TTwoPicSlider()
    : TControl(), lowerSurface(0), upperSurface(0), compositeSurface(0), splitPosition(0), mode(0) {
}

// SYNTHETIC: IMPERIALISM 0x0043d650
// TTwoPicSlider::`scalar deleting destructor'
TTwoPicSlider::~TTwoPicSlider() {}

// FUNCTION: IMPERIALISM 0x0056e200
void TTwoPicSlider::InitializePictureSurfaces(int baseBitmapId) {
  lowerSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(baseBitmapId + 1);
  upperSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(baseBitmapId);
  RECT bounds = {0, 0, frameWidth34, frameHeight38};
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&compositeSurface, 8, &bounds);
}

// FUNCTION: IMPERIALISM 0x0056e2f0
void TTwoPicSlider::Free() {
  if (lowerSurface != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&lowerSurface);
  }
  if (upperSurface != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&upperSurface);
  }
  if (compositeSurface != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&compositeSurface);
  }
  TView::Free();
}

namespace {

static __inline short ClampSliderSplitForFill(short splitPosition) {
  if (splitPosition < 0x0c) {
    return 0;
  }
  return splitPosition;
}

static __inline short ClampSliderInputToHeight(int height, int pointRecord) {
  int requested = *reinterpret_cast<short*>(pointRecord + 4);
  if (height <= requested) {
    requested = height;
  }
  if (requested < 1) {
    requested = 0;
  }
  return static_cast<short>(height - requested);
}

static __inline int SliderScaledValue(TTwoPicSlider* slider, int scale) {
  short adjustedSplit = 0;
  if (slider->splitPosition >= 0x0c) {
    adjustedSplit = static_cast<short>(slider->splitPosition - 0x0c);
  }
  return (adjustedSplit * scale) /
         static_cast<int>(static_cast<short>(slider->frameHeight38 - 0x0c));
}
} // namespace

// FUNCTION: IMPERIALISM 0x0056e370
void TTwoPicSlider::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  TTwoPicSlider* slider = this;
  // ORIG_CALLCONV: __thiscall; Mac CodeWarrior evidence calls this TTwoPicSlider::Draw.
  if ((slider->lowerSurface != 0) && (slider->upperSurface != 0) &&
      (slider->compositeSurface != 0)) {
    short splitPosition = ClampSliderSplitForFill(slider->splitPosition);

    RECT blitRect;
    blitRect.bottom = slider->frameHeight38;
    blitRect.left = 0;
    blitRect.top = blitRect.bottom - splitPosition;
    blitRect.right = slider->frameWidth34;

    ResetQuickDrawStrokeState();
    BlitQuickDrawSurfaces(slider->lowerSurface->GetBlitSurface(),
                          slider->compositeSurface->GetBlitSurface(), &blitRect, &blitRect, 0);

    blitRect.bottom = blitRect.top;
    blitRect.top = 0;
    BlitQuickDrawSurfaces(slider->upperSurface->GetBlitSurface(),
                          slider->compositeSurface->GetBlitSurface(), &blitRect, &blitRect, 0);

    blitRect.right = slider->frameWidth34;
    blitRect.bottom = slider->frameHeight38;
    blitRect.left = 0;
    blitRect.top = 0;
    BlitQuickDrawSurfaces(slider->compositeSurface->GetBlitSurface(),
                          g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect,
                          0);

    if (slider->splitPosition < 0x0c) {
      CString statusText;
      int textShadowColor = 0;
      int textMainColor = 0;

      g_pSimMgr->GetString(0x2743, 0x3b, &statusText);
      ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b6c);
      MapUiThemeCodeToStyleFlags(0x2b6c, &textShadowColor);
      MapUiThemeCodeToStyleFlags(0x2b67, &textMainColor);

      short textCenterY = static_cast<short>(slider->frameHeight38 / 2);
      short textWidth = MeasureTextExtentWithCachedQuickDrawStyle(&statusText);
      short textLeft = static_cast<short>((slider->frameWidth34 / 2) - (textWidth / 2));

      SetQuickDrawColorAndSyncGlobals(textMainColor);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(textLeft + 1),
                                              static_cast<short>(textCenterY + 5));
      DrawTextWithCachedQuickDrawStyleState(&statusText);

      SetQuickDrawColorAndSyncGlobals(textShadowColor);
      SetQuickDrawTextOriginWithContextOffset(textLeft, static_cast<short>(textCenterY + 4));
      DrawTextWithCachedQuickDrawStyleState(&statusText);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056e640
void TTwoPicSlider::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                   void* pEventDataA, void* pEventDataB,
                                                   int nCommandFlag) {
  (void)nCommandFlag;
  TTwoPicSlider* slider = this;
  // ORIG_CALLCONV: __thiscall; Mac CodeWarrior evidence calls this TTwoPicSlider::TrackMouse.
  (void)pEventSender;
  (void)pEventDataA;
  int pointRecord = reinterpret_cast<int>(pEventDataB);
  if (0 < nEventType) {
    if (2 < nEventType) {
      return;
    }

    short nextSplit = ClampSliderInputToHeight(slider->frameHeight38, pointRecord);
    if (slider->splitPosition != nextSplit) {
      slider->splitPosition = nextSplit;

      ScopedMapQuickDrawContextGuard quickDrawContext(slider);
      slider->Refresh();

      RECT sliderRect;
      sliderRect.left = 0;
      sliderRect.top = 0;
      sliderRect.right = slider->frameWidth34;
      sliderRect.bottom = slider->frameHeight38;
      slider->ApplyRectSlot110(&sliderRect);

      if (slider->mode == 1) {
        int volumeScalar = SliderScaledValue(slider, 0xff);
        // 0x593cb0 is a real TSoundPlayer thiscall (this callsite loads
        // ECX = [0x6a43ec] in the original, same as 0x5db66f).
        g_pSfxPlaybackSystem->ScaleAndApplyAuxOutputVolume(static_cast<short>(volumeScalar));
        // Original: mov eax,[0x6a20f8]; mov [eax+0x4e],di — the master-volume
        // preference slot (index 3, clamped 0..0xff by
        // InitializeOrLoadEntryArray14AndClampLimits) on the TSimMgr singleton.
        g_pSimMgr->preferenceValues[3] = static_cast<short>(volumeScalar);
      }
    }
  }

  if ((nEventType == 2) && (slider->mode == 2)) {
    int percent = SliderScaledValue(slider, 100);
    g_pSfxPlaybackSystem->SetMasterVolumeFromPercent(static_cast<short>(percent));
    g_pSfxPlaybackSystem->PlaySoundEffect(7000, 0, 1);
  }
}
