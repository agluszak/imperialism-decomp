#pragma once

#include "decomp_types.h"

extern "C" undefined4 ApplyHitRegionToClipState(void);
extern "C" void SnapshotHitRegionToClipCache(int* clipDescriptor);
extern "C" undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
extern "C" undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
extern "C" undefined4 ResetQuickDrawStrokeState(void);
extern "C" undefined4 thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(void);
extern "C" undefined4 thunk_DrawCenteredGuideLineOnMapDc(void);
extern "C" undefined4 thunk_RenderHintHelperWithCtrlModifierOverlay(void);
extern "C" undefined4 UpdatePaletteIndexWithDefaultFallback(void);
extern "C" undefined4 BlitRectWithOptionalTransparency(void);
extern "C" undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);

static __inline void SetQuickDrawTextOrigin(short x, short y) {
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(x, y);
}

static __inline void DrawCenteredGuideLine(short x, short y) {
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_DrawCenteredGuideLineOnMapDc)(x, y);
}

static __inline void SetQuickDrawStylePair(short styleA, short styleB) {
  reinterpret_cast<void(__cdecl*)(short, short)>(
      thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty)(styleA, styleB);
}

static __inline void ApplyRectClipRegion(int* rectBuffer) {
  reinterpret_cast<void(__cdecl*)(int*)>(thunk_ApplyRectClipRegionToGlobalClipState)(rectBuffer);
}

static __inline void SetQuickDrawFillColor(short color) {
  // This was missing! Let me check what thunk SetQuickDrawFillColor uses!
}
static __inline void CallUiRuntimeSlot34(UiRuntimeContext* runtimeContext, int styleIndex) {
  reinterpret_cast<void(__fastcall*)(UiRuntimeContext*, int)>(
      (*reinterpret_cast<void***>(runtimeContext))[0x34 / 4])(runtimeContext, styleIndex);
}
