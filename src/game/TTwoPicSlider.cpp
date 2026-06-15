// TTwoPicSlider draw/input vertical slice.

#include "decomp_types.h"
#include "game/TTwoPicSlider.h"
#include "game/generated/vcall_facades.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_globals.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/CString.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 BlitRectWithOptionalTransparency(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);
undefined4 thunk_MapUiThemeCodeToStyleFlags(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);
undefined4 WrapperFor_thunk_ApplyAuxOutputVolumeFromScalar_At00593cb0(void);

namespace {
const unsigned int kAddrLocalizationTable = 0x006A20F8;
const unsigned int kAddrSfxPlaybackSystem = 0x006A43EC;

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
  return (adjustedSplit * scale) / static_cast<int>(static_cast<short>(slider->field38 - 0x0c));
}
} // namespace

// FUNCTION: IMPERIALISM 0x0056e370
void TTwoPicSlider::DrawTwoPicSliderSplitOverlayAndCenteredStatusText() {
  TTwoPicSlider* slider = this;
  // ORIG_CALLCONV: __thiscall; Mac CodeWarrior evidence calls this TTwoPicSlider::Draw.
  if ((slider->lowerSurface != 0) && (slider->upperSurface != 0) &&
      (slider->compositeSurface != 0)) {
    short splitPosition = ClampSliderSplitForFill(slider->splitPosition);

    RECT blitRect;
    blitRect.bottom = slider->field38;
    blitRect.left = 0;
    blitRect.top = blitRect.bottom - splitPosition;
    blitRect.right = slider->field34;

    ResetQuickDrawStrokeState();
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(slider->lowerSurface + 4),
                                          reinterpret_cast<void*>(slider->compositeSurface + 4),
                                          &blitRect, &blitRect, 0, 0);

    blitRect.bottom = blitRect.top;
    blitRect.top = 0;
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(slider->upperSurface + 4),
                                          reinterpret_cast<void*>(slider->compositeSurface + 4),
                                          &blitRect, &blitRect, 0, 0);

    blitRect.right = slider->field34;
    blitRect.bottom = slider->field38;
    blitRect.left = 0;
    blitRect.top = 0;
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<void*>(slider->compositeSurface + 4),
        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &blitRect, &blitRect, 0, 0);

    if (slider->splitPosition < 0x0c) {
      CString statusText;
      int* statusTextRef = reinterpret_cast<int*>(&statusText);
      int textShadowColor = 0;
      int textMainColor = 0;

      void** localizationTable = *reinterpret_cast<void***>(kAddrLocalizationTable);
      reinterpret_cast<void(__cdecl*)(int, int, int*)>(localizationTable[0x21])(0x2743, 0x3b,
                                                                                statusTextRef);
      reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
      reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
          0x2b6c, reinterpret_cast<int>(&textShadowColor));
      reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
          0x2b67, reinterpret_cast<int>(&textMainColor));

      short textCenterY = static_cast<short>(slider->field38 / 2);
      short textWidth = static_cast<short>(
          reinterpret_cast<int(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)());
      short textLeft = static_cast<short>((slider->field34 / 2) - (textWidth / 2));

      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(textMainColor);
      reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
          static_cast<short>(textLeft + 1), static_cast<short>(textCenterY + 5));
      reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
          statusTextRef);

      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawColorAndSyncGlobals)(textShadowColor);
      reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
          textLeft, static_cast<short>(textCenterY + 4));
      reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
          statusTextRef);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056e640
void TTwoPicSlider::TrackTwoPicSliderMouseAndRefresh(int inputPhase, void* param2,
                                                     int pointRecord) {
  TTwoPicSlider* slider = this;
  // ORIG_CALLCONV: __thiscall; Mac CodeWarrior evidence calls this TTwoPicSlider::TrackMouse.
  (void)param2;
  if (0 < inputPhase) {
    if (2 < inputPhase) {
      return;
    }

    short nextSplit = ClampSliderInputToHeight(slider->field38, pointRecord);
    if (slider->splitPosition != nextSplit) {
      slider->splitPosition = nextSplit;

      ScopedMapQuickDrawContextGuard quickDrawContext(slider);
      slider->Refresh();

      RECT sliderRect;
      sliderRect.left = 0;
      sliderRect.top = 0;
      sliderRect.right = slider->field34;
      sliderRect.bottom = slider->field38;
      slider->ApplyRectSlot110(&sliderRect);

      if (slider->mode == 1) {
        int volumeScalar = SliderScaledValue(slider, 0xff);
        reinterpret_cast<void(__cdecl*)(int)>(
            WrapperFor_thunk_ApplyAuxOutputVolumeFromScalar_At00593cb0)(volumeScalar);
        *reinterpret_cast<short*>(kAddrLocalizationTable + 0x4e) = static_cast<short>(volumeScalar);
      }
    }
  }

  if ((inputPhase == 2) && (slider->mode == 2)) {
    int percent = SliderScaledValue(slider, 100);
    void** sfxPlaybackSystem = *reinterpret_cast<void***>(kAddrSfxPlaybackSystem);
    reinterpret_cast<void(__cdecl*)(int)>(sfxPlaybackSystem[0x2b])(percent);
    reinterpret_cast<void(__cdecl*)(int, int, int)>(sfxPlaybackSystem[0x2e])(7000, 0, 1);
  }
}
