// TCityProductionView temporary QuickDraw render-context slice.

#include "game/UiRuntimeContext.h"
#include "game/TView.h"
#include "game/generated/vcall_facades.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TCityProductionViewLayout {
  void* vftable;
  char pad_04[0xa2];
  unsigned char needsRefreshAtA6;
  char pad_a7;
  short currentMonthAtA8;
  short currentWeekAtAa;

  void RenderViewIntoPrimaryRenderContextWithTemporaryClip(int unusedArg1, int unusedArg2);
  void RenderNationHeaderDateLabelWithPeriodicRefresh();
};

undefined4 ApplyHitRegionToClipState(void);
undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
undefined4 thunk_GetActiveQuickDrawSurfaceContextAndFlags(void);
undefined4 thunk_SetActiveQuickDrawSurfaceContext(void);
void __cdecl SnapshotHitRegionToClipCache(int* clipDescriptor);

#include "game/diplomacy_globals.h"
extern "C" short g_Render_Nation_Header_Value_006961E0[12] = {0};
extern "C" short g_Render_Nation_Header_Value_006961F8[12] = {0};
extern "C" short g_Render_Nation_Header_Value_00696210[12] = {0};
extern "C" short g_Render_Nation_Header_Value_00696228[12] = {0};

undefined4 ResetQuickDrawStrokeState(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_DrawCenteredGuideLineOnMapDc(void);

struct RuntimeLocalTime {
  int tm_sec;
  int tm_min;
  short tm_hour;
};

undefined4 GetCurrentLocalEpochSecondsWithTimezoneCache(void);
undefined4 ConvertEpochSecondsToLocalTmWithDstAdjust(void);

extern int g_pPrimaryRenderSurfaceContext;

// FUNCTION: IMPERIALISM 0x004bc9b0
void TCityProductionViewLayout::RenderViewIntoPrimaryRenderContextWithTemporaryClip(
    int unusedArg1, int unusedArg2) {
  (void)unusedArg1;
  (void)unusedArg2;

  QuickDrawSurfaceGuard surface;

  int boundsRecord[4];
  reinterpret_cast<TView*>(this)->QueryBounds(boundsRecord);

  int clipRect[4];
  clipRect[0] = boundsRecord[0];
  clipRect[1] = boundsRecord[1];
  clipRect[2] = boundsRecord[2];
  clipRect[3] = boundsRecord[3];

  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(0);

  int* previousSurface = 0;
  int contextFlags = 0;
  reinterpret_cast<void(__cdecl*)(int**, int*)>(thunk_GetActiveQuickDrawSurfaceContextAndFlags)(
      &previousSurface, &contextFlags);

  reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
      reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext), contextFlags);
  reinterpret_cast<void(__cdecl*)(int*)>(thunk_ApplyRectClipRegionToGlobalClipState)(clipRect);

  needsRefreshAtA6 = 1;
  reinterpret_cast<TView*>(this)->ApplyRectSlot110(&boundsRecord[1]);

  reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
      previousSurface, contextFlags);
  SnapshotHitRegionToClipCache(0);
}

// FUNCTION: IMPERIALISM 0x004badd0
void TCityProductionViewLayout::RenderNationHeaderDateLabelWithPeriodicRefresh() {
  NationState* nationState = g_apNationStates[g_pUiRuntimeContext->GetActiveNationId()];
  void* subObject = 0;
  if (nationState != 0) {
    subObject = *reinterpret_cast<void**>(reinterpret_cast<char*>(nationState) + 0x894);
  }
  short sVar2_val = VCall_SecondaryState_HasNationFlag5C(subObject, 0xe);

  int mask1 = -(sVar2_val == 2);
  int mask2 = -(sVar2_val == 2);
  short originX = (mask1 & 0xffe9) + 0x213;
  short sVar2 = (mask2 & 0x14) + 0x6b;

  if (currentMonthAtA8 < 0) {
    int epochSeconds;
    reinterpret_cast<void(__cdecl*)(int*)>(GetCurrentLocalEpochSecondsWithTimezoneCache)(
        &epochSeconds);
    RuntimeLocalTime* tm = reinterpret_cast<RuntimeLocalTime*(__cdecl*)(const int*)>(
        ConvertEpochSecondsToLocalTmWithDstAdjust)(&epochSeconds);

    int iVar4 = tm->tm_min;
    short sVar6 = static_cast<short>(iVar4 / 5);
    currentWeekAtAa = sVar6;

    short sVar1 = tm->tm_hour;
    currentMonthAtA8 = sVar1;
    if (6 < sVar6) {
      currentMonthAtA8 = sVar1 + 1;
    }
    if (11 < currentMonthAtA8) {
      currentMonthAtA8 -= 12;
    }
    if (11 < currentMonthAtA8) {
      currentMonthAtA8 -= 12;
    }
  }

  reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
  g_pUiRuntimeContext->ApplyLegendSplitSlot34(1);
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
      originX, sVar2);

  short offset_x1 = g_Render_Nation_Header_Value_006961E0[currentMonthAtA8];
  short offset_y1 = g_Render_Nation_Header_Value_006961F8[currentMonthAtA8];
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_DrawCenteredGuideLineOnMapDc)(
      static_cast<short>(offset_x1 + originX), static_cast<short>(offset_y1 + sVar2));

  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColor)(0);
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(
      originX, sVar2);

  short offset_x2 = g_Render_Nation_Header_Value_00696210[currentWeekAtAa];
  short offset_y2 = g_Render_Nation_Header_Value_00696228[currentWeekAtAa];
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_DrawCenteredGuideLineOnMapDc)(
      static_cast<short>(offset_x2 + originX), static_cast<short>(offset_y2 + sVar2));
}
