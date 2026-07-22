#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

void SetQuickDrawFillColor(COLORREF fillColor);
void SetQuickDrawColorAndPropagateIfChanged(COLORREF newColor);
void SetQuickDrawStrokeColor(COLORREF strokeColor);
void SetQuickDrawColorAndSyncGlobals(COLORREF color);
void SetGlobalBlitTransparentColorRaw(COLORREF transparentColor);
void SetGlobalQuickDrawOrigin(short originX, short originY);
void SetQuickDrawPenSizeAndMarkDirty(short horizontalSize, short verticalSize);
void ResetQuickDrawStrokeState();
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect);

// Opaque classic QuickDraw cursor types. A CursHandle is a relocatable Handle,
// hence the pointer-to-pointer shape consumed by TView's GetCursor/SetCursor path.
struct QuickDrawCursor;
typedef QuickDrawCursor** QuickDrawCursorHandle;

// Windows compatibility stubs for the classic QuickDraw cursor API. The retail
// implementation only performs its availability assertion; GetCursor then returns
// a null handle and SetCursor otherwise has no effect.
void __cdecl SetQuickDrawCursor(const QuickDrawCursor* cursor);
QuickDrawCursorHandle __cdecl GetQuickDrawCursor(short cursorId);

void SetQuickDrawTextOriginWithContextOffset(short x, short y);
void DrawCenteredGuideLineOnMapDc(short x, short y);

struct TextStyle;

// Build a CFont from a packed text-style preset (mode=font family 0-4, flag2=bold/
// italic/underline bits, pointSize=size index): fixed-size families 2/3 map the size
// index through a height table, scalable families compute (index*10+3)/8; the face
// name comes from g_apszQuickDrawFontFaceNames. 0x00494130
CFont* __cdecl CreateFontFromPresetAndAttachRegionHandle(TextStyle* preset);

// Copy the preset into the global font-preset cache, rebuild the cached CFont if any
// field changed (or none exists yet), and return it. 0x004944e0
CFont* __cdecl UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(TextStyle* style);

// The TextStyle text-style / control-theme helpers (BuildUiTextStyleDescriptor,
// InitializeUiTextStyleDescriptor, ApplyControlThemeStyleAndOptionalCaption,
// ConfigureUiControlStyleValueAndCaptionFromStringResource,
// ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor, InitializeUiTextStyleDescriptorAndApplyQuickDraw,
// ResolveUiThemeColor) live in game/ui_text_label_helpers_decls.h -- they belong to the
// ui_text_label_helpers.cpp unit, not the QuickDraw surface/font engine.

// If paletteIndex is the sentinel -1 (as a short), resolves the nearest white entry
// from the default cached bitmap resource's palette instead. 0x004951e0
void UpdatePaletteIndexWithDefaultFallback(unsigned int paletteIndex);

// Cached-style text measurement leaf (0x494e00): rebuilds the cached measure-font from
// g_QuickDrawMeasureFontPreset if dirty, selects it into the active QuickDraw CDC (or a
// local compatible DC if none active), and returns the text width via
// GetTextExtentPoint32A. Ported in quickdraw_rendering.cpp.
short __cdecl MeasureTextExtentWithCachedQuickDrawStyle(const CString* text);

// Shrinks *text (dropping trailing characters and appending "...") until it fits
// within maxWidth; empties the string outright if that would leave under 5
// characters. 0x005d4c60
void TruncateTextToFitWidthWithEllipsis(CString* text, short maxWidth);

// Cached-style text draw leaf (0x494a90): rebuilds/selects the cached measure-font into
// the active QuickDraw CDC, applies the current QuickDraw text color, then draws at the
// resolved origin cached by SetQuickDrawTextOriginWithContextOffset.
void __cdecl DrawTextWithCachedQuickDrawStyleState(const CString* text);

// Cached-style rect text draw leaf (0x494bf0): same cached-font/color setup as
// DrawTextWithCachedQuickDrawStyleState, but draws into a caller rect via CDC::DrawText with
// a styleSel-selected format. Sole caller: TTradeScreenPicture::Draw.
void __cdecl RenderTradeScreenCommoditySummaryRows_Impl(CString* text, RECT* rect, short styleSel,
                                                        int unused);

// QuickDraw text-style words (txFont/txFace/txSize) write the corresponding fields of
// g_QuickDrawMeasureFontPreset (mode/flag2/pointSize) and mark the measure-font dirty
// (g_bQuickDrawMeasureFontDirty). Real game functions (the D:\Ambit\QuickDraw.cpp layer),
// ported in quickdraw_rendering.cpp.
void SetQuickDrawTextFont(short value); // 0x00495230 (txFont)
void SetQuickDrawTextFace(short value); // 0x00495290 (txFace)
void SetQuickDrawTextSize(short value); // 0x00495260 (txSize)

// Sets the QuickDraw fill color from a palette-table index. When a memory DC is active,
// resolves the palette entry to an RGB color; otherwise 0xff = black, <1 = white, and
// positive indices retain the PALETTEINDEX marker. 0x004950f0
void SetQuickDrawFillColorFromPaletteIndex(unsigned short paletteIndex);

// Windows no-op for the classic QuickDraw HiliteColor hook. RGBQUAD is the VC5-era
// Win32 GDI color record used by this Windows port. 0x00498ca0
void HiliteColor(const RGBQUAD* color);

// Selects the cached measure-font and draws a single character via CDC::TextOut at the
// resolved text origin (a per-unit letter overlay), then restores DC state. 0x00494950
void RenderTacticalBattleSelectionAndUnitOverlayPass_Impl(char glyph);

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
