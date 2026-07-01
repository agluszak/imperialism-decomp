#include "game/quickdraw_rendering.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"

extern void* g_pScopedMapQuickDrawDcHandleObject;

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

// TODO(shortcut): the real owner (InitializeGlobalClipRegionHandleState, 0x494040)
// constructs a small object (vtable @ 0x67106c + an HRGN member at +4) the first time
// the app needs a cached hit-region handle, registers it via RegisterClipRegionHandle,
// and stores it here. That owning class isn't modeled yet, so this lazily creates just
// the HRGN this one reader needs instead of the real object — g_pGlobalClipRegionHandleObject
// stays typed as a raw `int` (pre-existing, not introduced here) rather than a real
// pointer, and nothing calls RegisterClipRegionHandle for it the way the real ctor
// does. Fixes the crash (previously always-null, dereferenced offset+4 of a null
// pointer on first paint) but is not a full port of InitializeGlobalClipRegionHandleState.
static int* EnsureGlobalClipRegionHandleObject() {
  if (g_pGlobalClipRegionHandleObject == 0) {
    static int s_clipRegionHandleObject[2] = {0, 0};
    s_clipRegionHandleObject[1] = reinterpret_cast<int>(CreateRectRgn(0, 0, 0, 0));
    g_pGlobalClipRegionHandleObject = reinterpret_cast<int>(s_clipRegionHandleObject);
  }
  return reinterpret_cast<int*>(g_pGlobalClipRegionHandleObject);
}

// FUNCTION: IMPERIALISM 0x00495a30
void SnapshotHitRegionToClipCache(int* clipDescriptor) {
  HRGN* clipRegionHandle = reinterpret_cast<HRGN*>(EnsureGlobalClipRegionHandleObject() + 1);
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
    TBitmapSurfaceContextDescriptor* descriptor =
        static_cast<TBitmapSurfaceContextDescriptor*>(g_pActiveQuickDrawSurfaceContextHead);
    TBitmapSurfaceNode* node = descriptor->GetSurfaceNode();
    if (node != nullptr) {
      surfaceField1c = reinterpret_cast<int>(node->dib);
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
