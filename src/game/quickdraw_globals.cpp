#include "game/quickdraw_globals.h"

extern "C" int __stdcall CombineRgn(void* hrgnDest, void* hrgnSrc1, void* hrgnSrc2,
                                    int fnCombineMode);

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

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
// GLOBAL: IMPERIALISM 0x6a1d52
int g_uQuickDrawCurrentColor = 0;
// GLOBAL: IMPERIALISM 0x6a1d60
int g_pActiveQuickDrawSurfaceContext = 0;

// FUNCTION: IMPERIALISM 0x00495000
void SetQuickDrawFillColor(int fillColor) {
  g_Quick_Draw_Color_State_006950FC = fillColor;
  *reinterpret_cast<int*>(g_pActiveQuickDrawSurfaceContext + 0x28) = fillColor;
  g_uQuickDrawCurrentColor = fillColor;
}

// FUNCTION: IMPERIALISM 0x00495310
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB) {
  g_nQuickDrawStrokeStylePrimary = (int)styleParamA;
  g_nQuickDrawStrokeStyleSecondary = (int)styleParamB;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x00495a30
void SnapshotHitRegionToClipCache(int* clipDescriptor) {
  int clipObject = g_pGlobalClipRegionHandleObject;
  int regionSlot = *clipDescriptor + 0x14;
  if (regionSlot == 0) {
    CombineRgn(*reinterpret_cast<void**>(clipObject + 4), 0, 0, 5);
    return;
  }
  CombineRgn(*reinterpret_cast<void**>(clipObject + 4), *reinterpret_cast<void**>(regionSlot + 4),
             0, 5);
}
