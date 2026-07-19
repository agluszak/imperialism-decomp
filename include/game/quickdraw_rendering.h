#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

void SetQuickDrawFillColor(int fillColor);
void SetQuickDrawStrokeColor(int strokeColor);
// Clips srcRect to bounds, shifting dstRect by the same per-edge delta so the two
// stay in sync (the standard blit-clip prologue before a QuickDraw surface blit).
// Returns non-zero iff the clipped srcRect is still non-empty. 0x005a6940
BOOL __stdcall ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect);
void SetQuickDrawColorAndSyncGlobals(int color);
void SetGlobalBlitTransparentColorRaw(int transparentColor);
void MapUiThemeCodeToStyleFlags(short themeCode, int* outStyleFlags);
void SetGlobalQuickDrawOrigin(short originX, short originY);
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB);
void ResetQuickDrawStrokeState();
// Lazy stand-in for the unported static-init ctor at 0x494040; returns the global
// clip CRgn (g_pGlobalClipRegionHandleObject), creating it on first use.
CRgn* EnsureGlobalClipRegionHandleObject();
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect);

void SetQuickDrawTextOriginWithContextOffset(short x, short y);
void DrawCenteredGuideLineOnMapDc(short x, short y);

struct TControlPictureRectState;

// Build a CFont from a packed text-style preset (mode=font family 0-4, flag2=bold/
// italic/underline bits, pointSize=size index): fixed-size families 2/3 map the size
// index through a height table, scalable families compute (index*10+3)/8; the face
// name comes from g_apszQuickDrawFontFaceNames. 0x00494130
CFont* __cdecl CreateFontFromPresetAndAttachRegionHandle(TControlPictureRectState* preset);

// Copy the preset into the global font-preset cache, rebuild the cached CFont if any
// field changed (or none exists yet), and return it. 0x004944e0
CFont* __cdecl UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(TControlPictureRectState* style);

void BuildUiTextStyleDescriptor(TControlPictureRectState* styleDescriptor, int unused, int arg2,
                                int themeCode);
void InitializeUiTextStyleDescriptor(TControlPictureRectState* styleDescriptor, short face,
                                     short pointSize, int themeCode, short font);

// 0x5c4020 -- asserts the text control, applies a theme style descriptor built from
// themeCode (BuildUiTextStyleDescriptor inline-expanded in the original), sets the
// text theme code, and optionally assigns a caption string. Returns the control.
// unused2 is always 0 at every known call site.
class TStaticText;
TStaticText* ApplyControlThemeStyleAndOptionalCaption(TStaticText* control, int unused2,
                                                      int pointSize, int themeCode, int themeCode2,
                                                      const char* caption);

// 0x5c4180 -- same shape as ApplyControlThemeStyleAndOptionalCaption, but the caption
// text is loaded from a string-table resource (group/index) via
// g_pModuleLibraryCacheState instead of being passed as a literal pointer.
TStaticText* ConfigureUiControlStyleValueAndCaptionFromStringResource(
    TStaticText* control, int unused2, int pointSize, int themeCode, int themeCode2,
    int stringResourceGroup, short stringResourceIndex);

// If paletteIndex is the sentinel -1 (as a short), resolves it from the default
// cached bitmap resource's palette instead. 0x004951e0
void UpdatePaletteIndexWithDefaultFallback(unsigned int paletteIndex);
void ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(int unused, int styleWidth, int themeCode);
void InitializeUiTextStyleDescriptorAndApplyQuickDraw(short face, short pointSize, int themeCode,
                                                      short font);

// Cached-style text measurement leaf (0x494e00): rebuilds the cached measure-font from
// g_QuickDrawMeasureFontPreset if dirty, selects it into the active QuickDraw CDC (or a
// local compatible DC if none active), and returns the text width via
// GetTextExtentPoint32A. Ported in quickdraw_rendering.cpp.
short __cdecl MeasureTextExtentWithCachedQuickDrawStyle(const CString* text);

// Cached-style text draw leaf (0x494a90): rebuilds/selects the cached measure-font into
// the active QuickDraw CDC, applies the current QuickDraw text color, then draws at the
// resolved origin cached by SetQuickDrawTextOriginWithContextOffset.
void __cdecl DrawTextWithCachedQuickDrawStyleState(const CString* text);

static __inline void DrawTextWithCachedStyle(const CString* text) {
  DrawTextWithCachedQuickDrawStyleState(text);
}

// Cached-style rect text draw leaf (0x494bf0): same cached-font/color setup as
// DrawTextWithCachedQuickDrawStyleState, but draws into a caller rect via CDC::DrawText with
// a styleSel-selected format. Sole caller: TTradeScreenPicture::ApplyRectSlot110.
void __cdecl RenderTradeScreenCommoditySummaryRows_Impl(CString* text, RECT* rect, short styleSel,
                                                        int unused);

// QuickDraw text-style words (txFont/txFace/txSize) write the corresponding fields of
// g_QuickDrawMeasureFontPreset (mode/flag2/pointSize) and mark the measure-font dirty
// (g_bQuickDrawMeasureFontDirty). Real game functions (the D:\Ambit\QuickDraw.cpp layer),
// ported in quickdraw_rendering.cpp.
void SetQuickDrawTextFont(short value); // 0x00495230 (txFont)
void SetQuickDrawTextFace(short value); // 0x00495290 (txFace)
void SetQuickDrawTextSize(short value); // 0x00495260 (txSize)

static __inline void ApplyUiTextStyleAndSyncColor(int unused, int styleWidth, int themeCode) {
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(unused, styleWidth, themeCode);
}

static __inline void UpdatePaletteIndexWithFallback(int paletteIndex) {
  UpdatePaletteIndexWithDefaultFallback(static_cast<unsigned int>(paletteIndex));
}

// Sets the QuickDraw fill color from a palette-table index (0xff = black, <1 = white
// fallback, else index | 0x1000000). When a QuickDraw memory DC is active, the real
// body instead resolves the color from TMacViewMgr's resource-cache palette handle
// (same unrecovered-class gap as UpdatePaletteIndexWithDefaultFallback's -1 branch);
// left unmodeled. 0x004950f0
void SetQuickDrawFillColorFromPaletteIndex(unsigned short paletteIndex);

// Selects the cached measure-font and draws a single character via CDC::TextOut at the
// resolved text origin (a per-unit letter overlay), then restores DC state. 0x00494950
void RenderTacticalBattleSelectionAndUnitOverlayPass_Impl(char glyph);

// Draws four short corner-tick brackets around rect's edges (a hex-selection
// highlight idiom), shrinking rect->right/bottom by 1 first. 0x005a99e0
void __stdcall DrawHexSelectionOutlineSegments(RECT* rect);

// Classic "simulate TransparentBlt" masked-BitBlt technique (cf. Microsoft KB Q79212):
// builds a monochrome mask from sourceBitmap's pixels matching colorKey, uses it to AND
// out the transparent area of the destination background and the opaque area of the
// source image, then ORs the two together and blits the composited result onto destDc
// at (destX, destY). No xrefs found in the retail binary (dead code, or reached only via
// an unrecovered indirect call); ported directly from the decompile since the technique
// and every callee are fully understood Win32 GDI primitives. 0x00496450
void TransparentBlitBitmapUsingMaskedRasterOps(HDC destDc, HBITMAP sourceBitmap, short destX,
                                               short destY, COLORREF colorKey);

// Same technique as TransparentBlitBitmapUsingMaskedRasterOps, but blits only a
// (srcX, srcY, width, height) sub-region of the composited image instead of the whole
// bitmap. 0x004967e0
void TransparentBlitBitmapRegionUsingMaskedRasterOps(HDC destDc, HBITMAP sourceBitmap, short destX,
                                                     short destY, COLORREF colorKey, short srcX,
                                                     short srcY, short width, short height);
