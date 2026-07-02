#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

void SetQuickDrawFillColor(int fillColor);
void SetQuickDrawStrokeColor(int strokeColor);
void SetQuickDrawColorAndSyncGlobals(int color);
void SetGlobalBlitTransparentColorRaw(int transparentColor);
void MapUiThemeCodeToStyleFlags(short themeCode, int* outStyleFlags);
void SetGlobalQuickDrawOrigin(short originX, short originY);
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB);
void SnapshotHitRegionToClipCache(int* clipDescriptor);
void ResetQuickDrawStrokeState();
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect);

// QuickDraw clip region functions
undefined4 ApplyHitRegionToClipState(void);
undefined4 ApplyRectClipRegionToGlobalClipState(void);

void SetQuickDrawTextOriginWithContextOffset(short x, short y);
void DrawCenteredGuideLineOnMapDc(short x, short y);

undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);

// Cached-style text leaves (0x494a90 / 0x494e00) are not ported yet — they dispatch
// through the cached text-style context singletons (0x6a1da0 / 0x6a1d9c), which are
// real CDC* (see g_pQuickDrawMemoryDc / g_pScopedMapQuickDrawDcHandleObject). Until
// they're ported these stay the single shared typed entry points (Hard Rule 9: generic
// extern + typed cast), so call sites stay cast-free.
undefined4 MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 DrawTextWithCachedQuickDrawStyleState(void);

static __inline short MeasureTextExtentWithCachedStyle(const CString* text) {
  return reinterpret_cast<short(__cdecl*)(const CString*)>(
      reinterpret_cast<void (*)()>(MeasureTextExtentWithCachedQuickDrawStyle))(text);
}

static __inline void DrawTextWithCachedStyle(const CString* text) {
  reinterpret_cast<void(__cdecl*)(const CString*)>(
      reinterpret_cast<void (*)()>(DrawTextWithCachedQuickDrawStyleState))(text);
}

static __inline void ApplyUiTextStyleAndSyncColor(int unused, int styleWidth, int themeCode) {
  reinterpret_cast<void(__cdecl*)(int, int, int)>(reinterpret_cast<void (*)()>(
      ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor))(unused, styleWidth, themeCode);
}

static __inline void UpdatePaletteIndexWithFallback(int paletteIndex) {
  reinterpret_cast<void(__cdecl*)(int)>(
      reinterpret_cast<void (*)()>(UpdatePaletteIndexWithDefaultFallback))(paletteIndex);
}

struct ClipStateRegionWrapper;

// 0x494b60 — pushes the wrapper's region into the global clip state (original callers
// pass the QuickDrawSurfaceGuard's wrapper, or 0).
static __inline void ApplyHitRegionToClip(ClipStateRegionWrapper* wrapper) {
  reinterpret_cast<void(__cdecl*)(ClipStateRegionWrapper*)>(
      reinterpret_cast<void (*)()>(ApplyHitRegionToClipState))(wrapper);
}

static __inline void ApplyRectClipRegionToClip(RECT* clipRect) {
  reinterpret_cast<void(__cdecl*)(RECT*)>(
      reinterpret_cast<void (*)()>(ApplyRectClipRegionToGlobalClipState))(clipRect);
}
