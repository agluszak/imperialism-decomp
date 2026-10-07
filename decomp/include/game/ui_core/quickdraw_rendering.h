#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/quickdraw_types.h"

void SetQuickDrawFillColor(COLORREF fillColor);
void SetQuickDrawColorAndPropagateIfChanged(COLORREF newColor);
void SetQuickDrawStrokeColor(COLORREF strokeColor);
void SetQuickDrawColorAndSyncGlobals(COLORREF color);
void SetGlobalBlitTransparentColorRaw(COLORREF transparentColor);
void SetGlobalQuickDrawOrigin(short originX, short originY);
void SetQuickDrawPenSizeAndMarkDirty(short horizontalSize, short verticalSize);
void ResetQuickDrawStrokeState();
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect);

struct QuickDrawCursor;
typedef QuickDrawCursor** QuickDrawCursorHandle;

void __cdecl SetQuickDrawCursor(const QuickDrawCursor* cursor);
QuickDrawCursorHandle __cdecl GetQuickDrawCursor(short cursorId);

void SetQuickDrawTextOriginWithContextOffset(short x, short y);
void DrawCenteredGuideLineOnMapDc(short x, short y);

struct TextStyle;

CFont* __cdecl CreateFontFromPresetAndAttachRegionHandle(TextStyle* preset);

CFont* __cdecl UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(TextStyle* style);

void UpdatePaletteIndexWithDefaultFallback(QuickDrawPaletteIndex paletteIndex);

short __cdecl MeasureTextExtentWithCachedQuickDrawStyle(const CString* text);
short __cdecl MeasureTextRangeWithCachedQuickDrawStyle(const char* text, short offset,
                                                       short length); // 0x00494d20

void TruncateTextToFitWidthWithEllipsis(CString* text, short maxWidth);

void __cdecl DrawTextWithCachedQuickDrawStyleState(const CString* text);

void __cdecl RenderTradeScreenCommoditySummaryRows(CString* text, RECT* rect, short styleSel,
                                                   int unused);

void SetQuickDrawTextFont(short value); // 0x00495230 (txFont)
void SetQuickDrawTextFace(short value); // 0x00495290 (txFace)
void SetQuickDrawTextSize(short value); // 0x00495260 (txSize)

void SetQuickDrawFillColorFromPaletteIndex(unsigned short paletteIndex);
void __cdecl ConfigureWhiteQuickDrawPen(unsigned char widePen); // 0x0051e160

void HiliteColor(const RGBQUAD* color);

void RenderTacticalBattleSelectionAndUnitOverlayPass(char glyph);

void TransparentBlitBitmapUsingMaskedRasterOps(HDC destDc, HBITMAP sourceBitmap, short destX,
                                               short destY, COLORREF colorKey);

void TransparentBlitBitmapRegionUsingMaskedRasterOps(HDC destDc, HBITMAP sourceBitmap, short destX,
                                                     short destY, COLORREF colorKey, short srcX,
                                                     short srcY, short width, short height);
