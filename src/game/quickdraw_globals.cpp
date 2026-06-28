#include "game/quickdraw_globals.h"

#include "game/bitmap_descriptor_helpers.h"

extern void* g_pScopedMapQuickDrawDcHandleObject;

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// GLOBAL: IMPERIALISM 0x64b8f0
int g_Reset_Quick_Draw_Value_0064B8F0 = 0;
// GLOBAL: IMPERIALISM 0x64b8f4
int g_Reset_Quick_Draw_Value_0064B8F4 = 0;
// GLOBAL: IMPERIALISM 0x64b8f8
short g_Reset_Quick_Draw_WordState_0064B8F8 = 0;
// GLOBAL: IMPERIALISM 0x6a1d10
short g_Reset_Quick_Draw_State_006A1D10 = 0;

// GLOBAL: IMPERIALISM 0x6a1d08
int g_nQuickDrawStrokeStylePrimary = 0;
// GLOBAL: IMPERIALISM 0x6a1d0c
int g_nQuickDrawStrokeStyleSecondary = 0;
// GLOBAL: IMPERIALISM 0x6a1db4
int g_bQuickDrawStrokePairDirty = 0;
// GLOBAL: IMPERIALISM 0x6a1da8
int g_pGlobalClipRegionHandleObject = 0;
// GLOBAL: IMPERIALISM 0x6950fc
int g_Quick_Draw_Color_State_006950FC = 0;
// GLOBAL: IMPERIALISM 0x695100
int g_uQuickDrawStrokeColor = 0;
// GLOBAL: IMPERIALISM 0x6a1d52
int g_uQuickDrawCurrentColor = 0;
// GLOBAL: IMPERIALISM 0x6a1d80
int g_nQuickDrawOriginX = 0;
// GLOBAL: IMPERIALISM 0x6a1d84
int g_nQuickDrawOriginY = 0;

// FUNCTION: IMPERIALISM 0x00495000
void SetQuickDrawFillColor(int fillColor) {
  g_Quick_Draw_Color_State_006950FC = fillColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->quickDrawColor = fillColor;
  }
  g_uQuickDrawCurrentColor = fillColor;
}

// FUNCTION: IMPERIALISM 0x00495070
void SetQuickDrawStrokeColor(int strokeColor) {
  g_uQuickDrawStrokeColor = strokeColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->transparentBlitColor = strokeColor;
  }
}

// FUNCTION: IMPERIALISM 0x00495310
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB) {
  g_nQuickDrawStrokeStylePrimary = (int)styleParamA;
  g_nQuickDrawStrokeStyleSecondary = (int)styleParamB;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x004953a0
void ResetQuickDrawStrokeState() {
  g_nQuickDrawStrokeStylePrimary = g_Reset_Quick_Draw_Value_0064B8F0;
  g_nQuickDrawStrokeStyleSecondary = g_Reset_Quick_Draw_Value_0064B8F4;
  g_Reset_Quick_Draw_State_006A1D10 = g_Reset_Quick_Draw_WordState_0064B8F8;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x00495a30
void SnapshotHitRegionToClipCache(int* clipDescriptor) {
  HRGN* clipRegionHandle = reinterpret_cast<HRGN*>(g_pGlobalClipRegionHandleObject + 4);
  int descriptorHead = *clipDescriptor;
  if (descriptorHead + 0x14 == 0) {
    CombineRgn(*clipRegionHandle, nullptr, nullptr, 5);
    return;
  }
  CombineRgn(*clipRegionHandle, *reinterpret_cast<HRGN*>(descriptorHead + 0x18), nullptr, 5);
}

// FUNCTION: IMPERIALISM 0x00495b40
void SetGlobalQuickDrawOrigin(short originX, short originY) {
  g_nQuickDrawOriginX = originX;
  g_nQuickDrawOriginY = originY;
}

// FUNCTION: IMPERIALISM 0x00498980
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect) {
  CBrush brush;
  brush.CreateSolidBrush(static_cast<COLORREF>(g_Quick_Draw_Color_State_006950FC));

  RECT fillRect;
  CopyRect(&fillRect, rect);

  int surfaceField1c = 0;
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    surfaceField1c = 0;
  } else {
    void** surfaceSlot = reinterpret_cast<void**>(
        reinterpret_cast<char*>(g_pActiveQuickDrawSurfaceContextHead) + 0x24);
    if (surfaceSlot != nullptr && *surfaceSlot != nullptr) {
      surfaceField1c = *reinterpret_cast<int*>(static_cast<char*>(*surfaceSlot) + 0x1c);
    }
  }
  if (surfaceField1c == 0) {
    OffsetRect(&fillRect, g_nQuickDrawOriginX, g_nQuickDrawOriginY);
  }

  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = static_cast<CDC*>(g_pScopedMapQuickDrawDcHandleObject);
  }
  if (dc != nullptr) {
    FillRect(dc->GetSafeHdc(), &fillRect, static_cast<HBRUSH>(brush.GetSafeHandle()));
  }
}
