#include "game/quickdraw_globals.h"

extern "C" int __stdcall CombineRgn(void* hrgnDest, void* hrgnSrc1, void* hrgnSrc2,
                                    int fnCombineMode);

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
// GLOBAL: IMPERIALISM 0x6a1d52
int g_uQuickDrawCurrentColor = 0;

// FUNCTION: IMPERIALISM 0x00495000
void SetQuickDrawFillColor(int fillColor) {
  g_Quick_Draw_Color_State_006950FC = fillColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->quickDrawColor = fillColor;
  }
  g_uQuickDrawCurrentColor = fillColor;
}

// FUNCTION: IMPERIALISM 0x004953a0
void ResetQuickDrawStrokeState() {
  g_nQuickDrawStrokeStylePrimary = g_Reset_Quick_Draw_Value_0064B8F0;
  g_nQuickDrawStrokeStyleSecondary = g_Reset_Quick_Draw_Value_0064B8F4;
  g_Reset_Quick_Draw_State_006A1D10 = g_Reset_Quick_Draw_WordState_0064B8F8;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x00495310
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB) {
  g_nQuickDrawStrokeStylePrimary = (int)styleParamA;
  g_nQuickDrawStrokeStyleSecondary = (int)styleParamB;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x00495a30
void SnapshotHitRegionToClipCache(int* clipDescriptor) {
  void** clipRegionHandle =
      reinterpret_cast<void**>(g_pGlobalClipRegionHandleObject + 4);
  int descriptorHead = *clipDescriptor;
  if (descriptorHead + 0x14 == 0) {
    CombineRgn(*clipRegionHandle, 0, 0, 5);
    return;
  }
  CombineRgn(*clipRegionHandle, *reinterpret_cast<void**>(descriptorHead + 0x18), 0, 5);
}
