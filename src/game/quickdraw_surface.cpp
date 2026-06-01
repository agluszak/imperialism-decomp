// QuickDraw surface / clip-state helper functions (address-ordered).
//
// These are the shared QuickDraw drawing-state primitives invoked by the UI
// widget DrawAmt / Render* bodies (see src/game/trade_screen.cpp). They operate
// on a small set of global QuickDraw stroke/clip state objects.

#include "decomp_types.h"

extern "C" int __stdcall CombineRgn(void* hrgnDest, void* hrgnSrc1, void* hrgnSrc2,
                                    int fnCombineMode);

// The original QuickDraw helpers are compiled with frame-pointer omission.
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

// FUNCTION: IMPERIALISM 0x00495310
void __cdecl SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB) {
  g_nQuickDrawStrokeStylePrimary = (int)styleParamA;
  g_nQuickDrawStrokeStyleSecondary = (int)styleParamB;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x00495a30
void __cdecl SnapshotHitRegionToClipCache(int* clipDescriptor) {
  int clipObject = g_pGlobalClipRegionHandleObject;
  int regionSlot = *clipDescriptor + 0x14;
  if (regionSlot == 0) {
    CombineRgn(*reinterpret_cast<void**>(clipObject + 4), 0, 0, 5);
    return;
  }
  CombineRgn(*reinterpret_cast<void**>(clipObject + 4),
             *reinterpret_cast<void**>(regionSlot + 4), 0, 5);
}
