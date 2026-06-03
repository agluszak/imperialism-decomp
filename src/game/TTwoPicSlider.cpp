// TTwoPicSlider draw/input vertical slice.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/CString.h"
#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TTwoPicSliderLayout {
  void* vftable;
  char pad_04[0x30];
  int widthAt34;
  int heightAt38;
  char pad_3c[0x48];
  int lowerSurfaceAt84;
  int upperSurfaceAt88;
  int compositeSurfaceAt8c;
  short splitPositionAt90;
  char pad_92[2];
  int modeAt94;
};

undefined4 ResetQuickDrawStrokeState(void);
undefined4 BlitRectWithOptionalTransparency(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);
undefined4 thunk_MapUiThemeCodeToStyleFlags(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 SetQuickDrawColorAndSyncGlobals(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);
undefined4 WrapperFor_thunk_ApplyAuxOutputVolumeFromScalar_At00593cb0(void);

extern int g_pActiveQuickDrawSurfaceContext;

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

static __inline int SliderScaledValue(TTwoPicSliderLayout* slider, int scale) {
  short adjustedSplit = 0;
  if (slider->splitPositionAt90 >= 0x0c) {
    adjustedSplit = static_cast<short>(slider->splitPositionAt90 - 0x0c);
  }
  return (adjustedSplit * scale) / static_cast<int>(static_cast<short>(slider->heightAt38 - 0x0c));
}
}

// FUNCTION: IMPERIALISM 0x0056e370
void __fastcall DrawTwoPicSliderSplitOverlayAndCenteredStatusText(
    TTwoPicSliderLayout* slider, int unusedEdx) {
  // ORIG_CALLCONV: __thiscall; Mac CodeWarrior evidence calls this TTwoPicSlider::Draw.
  (void)unusedEdx;
  if ((slider->lowerSurfaceAt84 != 0) && (slider->upperSurfaceAt88 != 0) &&
      (slider->compositeSurfaceAt8c != 0)) {
    short splitPosition = ClampSliderSplitForFill(slider->splitPositionAt90);

    RECT blitRect;
    blitRect.bottom = slider->heightAt38;
    blitRect.left = 0;
    blitRect.top = blitRect.bottom - splitPosition;
    blitRect.right = slider->widthAt34;

    reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<void*>(slider->lowerSurfaceAt84 + 4),
        reinterpret_cast<void*>(slider->compositeSurfaceAt8c + 4), &blitRect, &blitRect, 0, 0);

    blitRect.bottom = blitRect.top;
    blitRect.top = 0;
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<void*>(slider->upperSurfaceAt88 + 4),
        reinterpret_cast<void*>(slider->compositeSurfaceAt8c + 4), &blitRect, &blitRect, 0, 0);

    blitRect.right = slider->widthAt34;
    blitRect.bottom = slider->heightAt38;
    blitRect.left = 0;
    blitRect.top = 0;
    reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<void*>(slider->compositeSurfaceAt8c + 4),
        reinterpret_cast<void*>(g_pActiveQuickDrawSurfaceContext + 4), &blitRect, &blitRect, 0,
        0);

    if (slider->splitPositionAt90 < 0x0c) {
      CString statusText;
      int* statusTextRef = reinterpret_cast<int*>(&statusText);
      int textShadowColor = 0;
      int textMainColor = 0;

      statusText.InitFromEmpty();
      void** localizationTable = *reinterpret_cast<void***>(kAddrLocalizationTable);
      reinterpret_cast<void(__cdecl*)(int, int, int*)>(localizationTable[0x21])(
          0x2743, 0x3b, statusTextRef);
      reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
      reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
          0x2b6c, reinterpret_cast<int>(&textShadowColor));
      reinterpret_cast<void(__cdecl*)(int, int)>(thunk_MapUiThemeCodeToStyleFlags)(
          0x2b67, reinterpret_cast<int>(&textMainColor));

      short textCenterY = static_cast<short>(slider->heightAt38 / 2);
      short textWidth = static_cast<short>(
          reinterpret_cast<int(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)());
      short textLeft = static_cast<short>((slider->widthAt34 / 2) - (textWidth / 2));

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
void __fastcall TrackTwoPicSliderMouseAndRefresh(TTwoPicSliderLayout* slider, int unusedEdx,
                                                 int inputPhase, void* param2,
                                                 int pointRecord) {
  // ORIG_CALLCONV: __thiscall; Mac CodeWarrior evidence calls this TTwoPicSlider::TrackMouse.
  (void)unusedEdx;
  (void)param2;
  if (0 < inputPhase) {
    if (2 < inputPhase) {
      return;
    }

    short nextSplit = ClampSliderInputToHeight(slider->heightAt38, pointRecord);
    if (slider->splitPositionAt90 != nextSplit) {
      slider->splitPositionAt90 = nextSplit;

      ScopedMapQuickDrawContextGuard quickDrawContext(slider);
      VCall_FocusAnimationView_RenderSlotF8(slider);

      RECT sliderRect;
      sliderRect.left = 0;
      sliderRect.top = 0;
      sliderRect.right = slider->widthAt34;
      sliderRect.bottom = slider->heightAt38;
      VCall_FocusAnimationView_ApplyRectSlot110(slider, &sliderRect.left);

      if (slider->modeAt94 == 1) {
        int volumeScalar = SliderScaledValue(slider, 0xff);
        reinterpret_cast<void(__cdecl*)(int)>(WrapperFor_thunk_ApplyAuxOutputVolumeFromScalar_At00593cb0)(
            volumeScalar);
        *reinterpret_cast<short*>(kAddrLocalizationTable + 0x4e) =
            static_cast<short>(volumeScalar);
      }
    }
  }

  if ((inputPhase == 2) && (slider->modeAt94 == 2)) {
    int percent = SliderScaledValue(slider, 100);
    void** sfxPlaybackSystem = *reinterpret_cast<void***>(kAddrSfxPlaybackSystem);
    reinterpret_cast<void(__cdecl*)(int)>(sfxPlaybackSystem[0x2b])(percent);
    reinterpret_cast<void(__cdecl*)(int, int, int)>(sfxPlaybackSystem[0x2e])(7000, 0, 1);
  }
}
