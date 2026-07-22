#include "game/quickdraw_rendering.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/CDib.h"
#include "game/CDibPal.h"
#include "game/global_data_tables.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TStaticText.h"
#include "game/ui_invalidation_guard.h"
#include <cstring>

// The QuickDraw clip/surface module state is seeded by a file-scope C++ object
// (at 0x6a1d58) whose constructor runs from the CRT static-init table (thunk
// 0x493fe0, entry 0x692648) before WinMain, and whose destructor is registered
// via atexit. It (a) points the active surface context at the sentinel and
// (b) allocates the global clip CRgn attached to an empty rect. SetClip/GetClip
// (quickdraw_regions.cpp) read g_pGlobalClipRegionHandleObject directly with no
// null-guard, exactly as the original does, so this initializer must run first.
// Declaring a real file-scope instance reproduces that CRT-init entry; its +0x8
// member is g_pActiveQuickDrawSurfaceContext (0x6a1d60) in the original layout.
// FIXME(0x494010): the atexit destructor (DeleteObject + delete the CRgn) is left
// unmarked because MSVC500 inlines this trivial dtor into the atexit thunk, so no
// standalone symbol exists at 0x494010 for reccmp to pair. If a non-inlined shape
// is found, restore the `// FUNCTION: IMPERIALISM 0x00494010` marker here.
class TQuickDrawClipStateInitializer {
public:
  TQuickDrawClipStateInitializer();

  ~TQuickDrawClipStateInitializer() {
    g_pGlobalClipRegionHandleObject->DeleteObject();
    delete g_pGlobalClipRegionHandleObject;
  }
};

// FUNCTION: IMPERIALISM 0x00494040
TQuickDrawClipStateInitializer::TQuickDrawClipStateInitializer() {
  g_pActiveQuickDrawSurfaceContext = &g_defaultQuickDrawSurfaceSentinel;
  g_pGlobalClipRegionHandleObject = new CRgn;
  g_pGlobalClipRegionHandleObject->Attach(::CreateRectRgn(0, 0, 0, 0));
}

static TQuickDrawClipStateInitializer g_quickDrawClipStateInitializer;

// FUNCTION: IMPERIALISM 0x00494130
CFont* __cdecl CreateFontFromPresetAndAttachRegionHandle(TextStyle* preset) {
  // Height table for the fixed-size families (indices are size codes 1-0x18); the
  // original builds it on the stack every call.
  int heightBySizeIndex[25];
  heightBySizeIndex[0] = 0;
  heightBySizeIndex[1] = 1;
  heightBySizeIndex[2] = 2;
  heightBySizeIndex[3] = 3;
  heightBySizeIndex[4] = 4;
  heightBySizeIndex[5] = 5;
  heightBySizeIndex[6] = 6;
  heightBySizeIndex[7] = 7;
  heightBySizeIndex[8] = 8;
  heightBySizeIndex[9] = 0xe;
  heightBySizeIndex[10] = 0xe;
  heightBySizeIndex[11] = 0xf;
  heightBySizeIndex[12] = 0x10;
  heightBySizeIndex[13] = 0x11;
  heightBySizeIndex[14] = 0x14;
  heightBySizeIndex[15] = 0x14;
  heightBySizeIndex[16] = 0x14;
  heightBySizeIndex[17] = 0x14;
  heightBySizeIndex[18] = 0x14;
  heightBySizeIndex[19] = 0x14;
  heightBySizeIndex[20] = 0x19;
  heightBySizeIndex[21] = 0x19;
  heightBySizeIndex[22] = 0x19;
  heightBySizeIndex[23] = 0x19;
  heightBySizeIndex[24] = 0x1e;

  int sizeIndex = 0xc;
  if (preset->fontSize != 0) {
    sizeIndex = preset->fontSize;
  }
  int family = preset->fontFamily;
  if (family < 1 || family > 4) {
    family = 0;
  }

  int height;
  if (family == 0 || family == 1 || family == 4 || sizeIndex < 1 || sizeIndex > 0x18) {
    height = (sizeIndex * 10 + 3) / 8;
  } else {
    height = heightBySizeIndex[sizeIndex];
  }

  CFont* font = new CFont();
  LOGFONTA logFont;
  memset(&logFont, 0, sizeof(LOGFONTA));
  logFont.lfCharSet = DEFAULT_CHARSET;
  logFont.lfHeight = height;
  lstrcpynA(logFont.lfFaceName, g_apszQuickDrawFontFaceNames[family], 0x20);
  if ((preset->fontStyleFlags & 1) != 0) {
    logFont.lfWeight = 700;
  }
  logFont.lfItalic = static_cast<unsigned char>(preset->fontStyleFlags & 2);
  logFont.lfUnderline = static_cast<unsigned char>(preset->fontStyleFlags & 4);
  font->Attach(CreateFontIndirectA(&logFont));
  return font;
}

// FUNCTION: IMPERIALISM 0x004944e0
CFont* __cdecl UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(TextStyle* style) {
  if (g_QuickDrawCachedFontPreset.fontFamily != style->fontFamily) {
    g_bQuickDrawCachedFontDirty = 1;
    g_QuickDrawCachedFontPreset.fontFamily = style->fontFamily;
  }
  if (g_QuickDrawCachedFontPreset.fontStyleFlags != style->fontStyleFlags) {
    g_bQuickDrawCachedFontDirty = 1;
    g_QuickDrawCachedFontPreset.fontStyleFlags = style->fontStyleFlags;
  }
  if (g_QuickDrawCachedFontPreset.fontSize != style->fontSize) {
    g_bQuickDrawCachedFontDirty = 1;
    g_QuickDrawCachedFontPreset.fontSize = style->fontSize;
  }
  if (g_bQuickDrawCachedFontDirty != 0 || g_pQuickDrawCachedUiFont == 0) {
    if (g_pQuickDrawCachedUiFont != 0) {
      delete g_pQuickDrawCachedUiFont;
    }
    g_pQuickDrawCachedUiFont =
        CreateFontFromPresetAndAttachRegionHandle(&g_QuickDrawCachedFontPreset);
    g_bQuickDrawCachedFontDirty = 0;
  }
  return g_pQuickDrawCachedUiFont;
}

// FUNCTION: IMPERIALISM 0x00494950
void RenderTacticalBattleSelectionAndUnitOverlayPass_Impl(char glyph) {
  if (g_bQuickDrawMeasureFontDirty != 0 || g_pQuickDrawCachedMeasureFont == 0) {
    if (g_pQuickDrawCachedMeasureFont != 0) {
      delete g_pQuickDrawCachedMeasureFont;
    }
    g_pQuickDrawCachedMeasureFont =
        CreateFontFromPresetAndAttachRegionHandle(&g_QuickDrawMeasureFontPreset);
    g_bQuickDrawMeasureFontDirty = 0;
  }
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  CFont* prevFont = static_cast<CFont*>(dc->SelectObject(g_pQuickDrawCachedMeasureFont));
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetTextColor(static_cast<COLORREF>(g_QuickDrawMeasureFontPreset.textColor));
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetMapperFlags(1);
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  UINT prevAlign = dc->SetTextAlign(0x18);
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  char ch = glyph;
  dc->TextOut(g_nQuickDrawResolvedTextOriginX, g_nQuickDrawResolvedTextOriginY, &ch, 1);
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetTextAlign(prevAlign);
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SelectObject(prevFont);
}

// FUNCTION: IMPERIALISM 0x00494a90
void __cdecl DrawTextWithCachedQuickDrawStyleState(const CString* text) {
  if (g_bQuickDrawMeasureFontDirty != 0 || g_pQuickDrawCachedMeasureFont == 0) {
    if (g_pQuickDrawCachedMeasureFont != 0) {
      delete g_pQuickDrawCachedMeasureFont;
    }
    g_pQuickDrawCachedMeasureFont =
        CreateFontFromPresetAndAttachRegionHandle(&g_QuickDrawMeasureFontPreset);
    g_bQuickDrawMeasureFontDirty = 0;
  }

  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  CFont* oldFont = dc->SelectObject(g_pQuickDrawCachedMeasureFont);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetTextColor(static_cast<COLORREF>(g_QuickDrawMeasureFontPreset.textColor));

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  // The original calls CDC::SetMapperFlags(1) here. This is not the Win32
  // background-mode setter: it configures the font mapper before TextOut.
  dc->SetMapperFlags(1);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  UINT oldTextAlign = dc->SetTextAlign(TA_BASELINE | TA_NOUPDATECP);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->TextOut(g_nQuickDrawResolvedTextOriginX, g_nQuickDrawResolvedTextOriginY, (LPCSTR)*text,
              text->GetLength());

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetTextAlign(oldTextAlign);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SelectObject(oldFont);
}

// Draws one text cell into a rect with the cached QuickDraw measure-font/color state, the
// same font-rebuild + SelectObject/SetTextColor idiom as DrawTextWithCachedQuickDrawStyleState
// (0x494a90) but using CDC::DrawText into a caller rect; styleSel selects the DrawText format
// flags. Only called by TTradeScreenPicture::Draw.
// FUNCTION: IMPERIALISM 0x00494bf0
void __cdecl RenderTradeScreenCommoditySummaryRows_Impl(CString* text, RECT* rect, short styleSel,
                                                        int unused) {
  int sel = styleSel; // compared as a sign-extended int in the original (movsx + cmp eax)
  int drawFormat = 0x920;
  if (sel != -2) {
    if (sel == -1) {
      drawFormat = 0x922;
    } else if (sel == 1) {
      drawFormat = 0x921;
    }
  }

  if (g_bQuickDrawMeasureFontDirty != 0 || g_pQuickDrawCachedMeasureFont == 0) {
    if (g_pQuickDrawCachedMeasureFont != 0) {
      delete g_pQuickDrawCachedMeasureFont;
    }
    g_pQuickDrawCachedMeasureFont =
        CreateFontFromPresetAndAttachRegionHandle(&g_QuickDrawMeasureFontPreset);
    g_bQuickDrawMeasureFontDirty = 0;
  }

  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  CFont* oldFont = dc->SelectObject(g_pQuickDrawCachedMeasureFont);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetTextColor(static_cast<COLORREF>(g_QuickDrawMeasureFontPreset.textColor));

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SetMapperFlags(1);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->DrawText((LPCSTR)*text, text->GetLength(), rect, drawFormat);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SelectObject(oldFont);
}

// FUNCTION: IMPERIALISM 0x00494e00
short __cdecl MeasureTextExtentWithCachedQuickDrawStyle(const CString* text) {
  // Active-DC path: reuse the global QuickDraw CDC, SelectObject the cached measure-font
  // around a GetTextExtentPointA. Falls back to g_pScopedMapQuickDrawDcHandleObject
  // when no memory DC is bound (same null-fallback chain as the other draw leaves).
  CDC* activeDc = g_pQuickDrawMemoryDc;
  if (activeDc == nullptr) {
    activeDc = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (activeDc != nullptr) {
    // Inlined rebuild of the cached measure-font (same shape as the draw-font rebuild
    // in UpdateGlobalFontPresetAndRebuildCachedFontIfDirty, but for the measure cluster).
    if (g_bQuickDrawMeasureFontDirty != 0 || g_pQuickDrawCachedMeasureFont == 0) {
      if (g_pQuickDrawCachedMeasureFont != 0) {
        delete g_pQuickDrawCachedMeasureFont;
      }
      g_pQuickDrawCachedMeasureFont =
          CreateFontFromPresetAndAttachRegionHandle(&g_QuickDrawMeasureFontPreset);
      g_bQuickDrawMeasureFontDirty = 0;
    }
    CFont* oldFont = activeDc->SelectObject(g_pQuickDrawCachedMeasureFont);
    SIZE extent;
    GetTextExtentPointA(activeDc->GetSafeHdc(), (LPCSTR)*text, text->GetLength(), &extent);
    activeDc->SelectObject(oldFont);
    return static_cast<short>(extent.cx);
  }
  // Local-DC path: no active QuickDraw DC, so build a throwaway compatible DC, select
  // the cached font into it, measure, restore, and destroy. The original wraps this in
  // an SEH frame for the stack CDC's destructor; real C++ construction/destruction emits
  // the same unwind via MSVC's EH machinery.
  CDC localDc;
  localDc.Attach(CreateCompatibleDC(static_cast<HDC>(0)));
  if (g_bQuickDrawMeasureFontDirty != 0 || g_pQuickDrawCachedMeasureFont == 0) {
    if (g_pQuickDrawCachedMeasureFont != 0) {
      delete g_pQuickDrawCachedMeasureFont;
    }
    g_pQuickDrawCachedMeasureFont =
        CreateFontFromPresetAndAttachRegionHandle(&g_QuickDrawMeasureFontPreset);
    g_bQuickDrawMeasureFontDirty = 0;
  }
  CFont* oldFont = localDc.SelectObject(g_pQuickDrawCachedMeasureFont);
  SIZE extent;
  GetTextExtentPointA(localDc.GetSafeHdc(), (LPCSTR)*text, text->GetLength(), &extent);
  localDc.SelectObject(oldFont);
  return static_cast<short>(extent.cx);
}

// FUNCTION: IMPERIALISM 0x00495000
void SetQuickDrawFillColor(COLORREF fillColor) {
  g_QuickDrawForegroundColor = fillColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->blitSurface.foregroundColor = fillColor;
  }
  g_QuickDrawMeasureFontPreset.textColor = fillColor;
}

// Sets the current QuickDraw draw color, propagating it to the active surface context and the
// cached measure-font style ref, but only when it actually changed.
// FUNCTION: IMPERIALISM 0x00495030
void SetQuickDrawColorAndPropagateIfChanged(COLORREF newColor) {
  if (g_QuickDrawForegroundColor != newColor) {
    g_QuickDrawForegroundColor = newColor;
    g_pActiveQuickDrawSurfaceContext->blitSurface.foregroundColor = newColor;
    g_QuickDrawMeasureFontPreset.textColor = newColor;
  }
}

// FUNCTION: IMPERIALISM 0x00495070
void SetQuickDrawStrokeColor(COLORREF strokeColor) {
  g_QuickDrawBackgroundColor = strokeColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->blitSurface.backgroundColor = strokeColor;
  }
}

// FUNCTION: IMPERIALISM 0x004950a0
void SetQuickDrawColorAndSyncGlobals(COLORREF color) {
  g_QuickDrawForegroundColor = color;
  g_pActiveQuickDrawSurfaceContext->blitSurface.foregroundColor = color;
  g_QuickDrawMeasureFontPreset.textColor = color;
}

// FUNCTION: IMPERIALISM 0x004950d0
void SetGlobalBlitTransparentColorRaw(COLORREF transparentColor) {
  g_QuickDrawBackgroundColor = transparentColor;
}

// FUNCTION: IMPERIALISM 0x004950f0
void SetQuickDrawFillColorFromPaletteIndex(unsigned short paletteIndex) {
  if (g_pQuickDrawMemoryDc != nullptr) {
    CDibPal* palette = g_pModuleLibraryCacheState->EnsureDefaultDibPalette();
    PALETTEENTRY entries[2];
    palette->GetPaletteEntries(static_cast<short>(paletteIndex), 1, entries);
    SetQuickDrawFillColor(RGB(entries[0].peRed, entries[0].peGreen, entries[0].peBlue));
    return;
  }
  if (paletteIndex == 0xff) {
    SetQuickDrawFillColor(0);
  } else if (static_cast<short>(paletteIndex) < 1) {
    SetQuickDrawFillColor(0xffffff);
  } else {
    SetQuickDrawFillColor(PALETTEINDEX(paletteIndex));
  }
}

// FUNCTION: IMPERIALISM 0x004951e0
void UpdatePaletteIndexWithDefaultFallback(QuickDrawPaletteIndex paletteIndex) {
  if (static_cast<short>(paletteIndex) == -1) {
    CDibPal* palette = g_pModuleLibraryCacheState->EnsureDefaultDibPalette();
    paletteIndex = palette->GetNearestPaletteIndex(RGB(0xff, 0xff, 0xff));
  }
  g_QuickDrawBackgroundColor = PALETTEINDEX(paletteIndex);
}

// FUNCTION: IMPERIALISM 0x00495230
void SetQuickDrawTextFont(short value) {
  if (g_QuickDrawMeasureFontPreset.fontFamily != value) {
    g_QuickDrawMeasureFontPreset.fontFamily = value;
    g_bQuickDrawMeasureFontDirty = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00495260
void SetQuickDrawTextSize(short value) {
  if (g_QuickDrawMeasureFontPreset.fontSize != value) {
    g_QuickDrawMeasureFontPreset.fontSize = value;
    g_bQuickDrawMeasureFontDirty = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00495290
void SetQuickDrawTextFace(short value) {
  if (g_QuickDrawMeasureFontPreset.fontStyleFlags != value) {
    g_QuickDrawMeasureFontPreset.fontStyleFlags = value;
    g_bQuickDrawMeasureFontDirty = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00495310
void SetQuickDrawPenSizeAndMarkDirty(short horizontalSize, short verticalSize) {
  g_nQuickDrawPenHorizontalSize = static_cast<int>(horizontalSize);
  g_nQuickDrawPenVerticalSize = static_cast<int>(verticalSize);
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x004953a0
void ResetQuickDrawStrokeState() {
  g_nQuickDrawPenHorizontalSize = g_Reset_Quick_Draw_Value_0064B8F0;
  g_nQuickDrawPenVerticalSize = g_Reset_Quick_Draw_Value_0064B8F4;
  g_Reset_Quick_Draw_State_006A1D10 = g_Reset_Quick_Draw_WordState_0064B8F8;
  g_bQuickDrawStrokePairDirty = 1;
}

// FUNCTION: IMPERIALISM 0x00495b40
void SetGlobalQuickDrawOrigin(short originX, short originY) {
  g_nQuickDrawOriginX = originX;
  g_nQuickDrawOriginY = originY;
}

// FUNCTION: IMPERIALISM 0x00496450
void TransparentBlitBitmapUsingMaskedRasterOps(HDC destDc, HBITMAP sourceBitmap, short destX,
                                               short destY, COLORREF colorKey) {
  HDC hdcSrc = CreateCompatibleDC(destDc);
  SelectObject(hdcSrc, sourceBitmap);
  BITMAP bm;
  GetObjectA(sourceBitmap, sizeof(BITMAP), &bm);
  POINT size;
  size.x = bm.bmWidth;
  size.y = bm.bmHeight;
  DPtoLP(hdcSrc, &size, 1);

  HDC hdcInverse = CreateCompatibleDC(destDc);
  HDC hdcMask = CreateCompatibleDC(destDc);
  HDC hdcResult = CreateCompatibleDC(destDc);
  HDC hdcSave = CreateCompatibleDC(destDc);

  HBITMAP bmpInverse = CreateBitmap(size.x, size.y, 1, 1, nullptr);
  HBITMAP bmpMask = CreateBitmap(size.x, size.y, 1, 1, nullptr);
  HBITMAP bmpResult = CreateCompatibleBitmap(destDc, size.x, size.y);
  HBITMAP bmpSave = CreateCompatibleBitmap(destDc, size.x, size.y);

  HGDIOBJ oldInverse = SelectObject(hdcInverse, bmpInverse);
  HGDIOBJ oldMask = SelectObject(hdcMask, bmpMask);
  HGDIOBJ oldResult = SelectObject(hdcResult, bmpResult);
  HGDIOBJ oldSave = SelectObject(hdcSave, bmpSave);

  int mapMode = GetMapMode(destDc);
  SetMapMode(hdcSrc, mapMode);

  BitBlt(hdcSave, 0, 0, size.x, size.y, hdcSrc, 0, 0, SRCCOPY);
  COLORREF oldBkColor = SetBkColor(hdcSrc, colorKey);
  BitBlt(hdcMask, 0, 0, size.x, size.y, hdcSrc, 0, 0, SRCCOPY);
  SetBkColor(hdcSrc, oldBkColor);
  BitBlt(hdcInverse, 0, 0, size.x, size.y, hdcMask, 0, 0, NOTSRCCOPY);
  BitBlt(hdcResult, 0, 0, size.x, size.y, destDc, destX, destY, SRCCOPY);
  BitBlt(hdcResult, 0, 0, size.x, size.y, hdcMask, 0, 0, SRCAND);
  BitBlt(hdcSrc, 0, 0, size.x, size.y, hdcInverse, 0, 0, SRCAND);
  BitBlt(hdcResult, 0, 0, size.x, size.y, hdcSrc, 0, 0, SRCPAINT);
  BitBlt(destDc, destX, destY, size.x, size.y, hdcResult, 0, 0, SRCCOPY);
  BitBlt(hdcSrc, 0, 0, size.x, size.y, hdcSave, 0, 0, SRCCOPY);

  DeleteObject(SelectObject(hdcInverse, oldInverse));
  DeleteObject(SelectObject(hdcMask, oldMask));
  DeleteObject(SelectObject(hdcResult, oldResult));
  DeleteObject(SelectObject(hdcSave, oldSave));
  DeleteDC(hdcResult);
  DeleteDC(hdcInverse);
  DeleteDC(hdcMask);
  DeleteDC(hdcSave);
  DeleteDC(hdcSrc);
}

// FUNCTION: IMPERIALISM 0x004967e0
void TransparentBlitBitmapRegionUsingMaskedRasterOps(HDC destDc, HBITMAP sourceBitmap, short destX,
                                                     short destY, COLORREF colorKey, short srcX,
                                                     short srcY, short width, short height) {
  HDC hdcSrc = CreateCompatibleDC(destDc);
  SelectObject(hdcSrc, sourceBitmap);
  BITMAP bm;
  GetObjectA(sourceBitmap, sizeof(BITMAP), &bm);
  POINT size;
  size.x = bm.bmWidth;
  size.y = bm.bmHeight;
  DPtoLP(hdcSrc, &size, 1);

  HDC hdcInverse = CreateCompatibleDC(destDc);
  HDC hdcMask = CreateCompatibleDC(destDc);
  HDC hdcResult = CreateCompatibleDC(destDc);
  HDC hdcSave = CreateCompatibleDC(destDc);

  HBITMAP bmpInverse = CreateBitmap(size.x, size.y, 1, 1, nullptr);
  HBITMAP bmpMask = CreateBitmap(size.x, size.y, 1, 1, nullptr);
  HBITMAP bmpResult = CreateCompatibleBitmap(destDc, size.x, size.y);
  HBITMAP bmpSave = CreateCompatibleBitmap(destDc, size.x, size.y);

  HGDIOBJ oldInverse = SelectObject(hdcInverse, bmpInverse);
  HGDIOBJ oldMask = SelectObject(hdcMask, bmpMask);
  HGDIOBJ oldResult = SelectObject(hdcResult, bmpResult);
  HGDIOBJ oldSave = SelectObject(hdcSave, bmpSave);

  int mapMode = GetMapMode(destDc);
  SetMapMode(hdcSrc, mapMode);

  BitBlt(hdcSave, 0, 0, size.x, size.y, hdcSrc, 0, 0, SRCCOPY);
  COLORREF oldBkColor = SetBkColor(hdcSrc, colorKey);
  BitBlt(hdcMask, 0, 0, size.x, size.y, hdcSrc, 0, 0, SRCCOPY);
  SetBkColor(hdcSrc, oldBkColor);
  BitBlt(hdcInverse, 0, 0, size.x, size.y, hdcMask, 0, 0, NOTSRCCOPY);
  BitBlt(hdcResult, 0, 0, size.x, size.y, destDc, destX, destY, SRCCOPY);
  BitBlt(hdcResult, 0, 0, size.x, size.y, hdcMask, 0, 0, SRCAND);
  BitBlt(hdcSrc, 0, 0, size.x, size.y, hdcInverse, 0, 0, SRCAND);
  BitBlt(hdcResult, 0, 0, size.x, size.y, hdcSrc, 0, 0, SRCPAINT);
  BitBlt(destDc, destX, destY, width, height, hdcResult, srcX, srcY, SRCCOPY);
  BitBlt(hdcSrc, 0, 0, size.x, size.y, hdcSave, 0, 0, SRCCOPY);

  DeleteObject(SelectObject(hdcInverse, oldInverse));
  DeleteObject(SelectObject(hdcMask, oldMask));
  DeleteObject(SelectObject(hdcResult, oldResult));
  DeleteObject(SelectObject(hdcSave, oldSave));
  DeleteDC(hdcResult);
  DeleteDC(hdcInverse);
  DeleteDC(hdcMask);
  DeleteDC(hdcSave);
  DeleteDC(hdcSrc);
}

// FUNCTION: IMPERIALISM 0x00496d40
void __cdecl BlitRectWithOptionalTransparency(TQuickDrawBlitSurface* srcSurface,
                                              TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                              RECT* dstRect, unsigned char blitFlags,
                                              RgnHandle clipRegion) {
  if (clipRegion != 0) {
    CDC* clipDc = g_pQuickDrawMemoryDc;
    if (clipDc == 0) {
      clipDc = g_pScopedMapQuickDrawDcHandleObject;
    }
    clipDc->SelectClipRgn(&(*clipRegion)->rgn);
  }

  if (dstSurface == g_defaultQuickDrawSurfaceSentinel.GetBlitSurface() || clipRegion != 0) {
    CDC* destinationDc = g_pQuickDrawMemoryDc;
    if (destinationDc == 0) {
      destinationDc = g_pScopedMapQuickDrawDcHandleObject;
    }
    g_pModuleLibraryCacheState->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(destinationDc,
                                                                                  FALSE);

    if ((blitFlags & 0x24) == 0x24) {
      destinationDc = g_pQuickDrawMemoryDc;
      if (destinationDc == 0) {
        destinationDc = g_pScopedMapQuickDrawDcHandleObject;
      }
      srcSurface->surfaceDib->StretchDibitsWithCopiedPaletteTable(
          destinationDc, 0x10, dstRect->left + g_nQuickDrawOriginX,
          dstRect->top + g_nQuickDrawOriginY, CRect(dstRect).Width(), CRect(dstRect).Height(),
          srcRect->left, srcRect->top, CRect(srcRect).Width(), CRect(srcRect).Height());
    } else {
      CDC sourceDc;
      CDC* compatibleDc = g_pQuickDrawMemoryDc;
      if (compatibleDc == 0) {
        compatibleDc = g_pScopedMapQuickDrawDcHandleObject;
      }
      sourceDc.Attach(CreateCompatibleDC(compatibleDc->GetSafeHdc()));
      HGDIOBJ previousBitmap =
          SelectObject(sourceDc.GetSafeHdc(), srcSurface->surfaceDib->m_hBitmap);

      if (dstSurface == g_defaultQuickDrawSurfaceSentinel.GetBlitSurface()) {
        destinationDc = g_pQuickDrawMemoryDc;
        if (destinationDc == 0) {
          destinationDc = g_pScopedMapQuickDrawDcHandleObject;
        }
        BitBlt(destinationDc->m_hDC, dstRect->left + g_nQuickDrawOriginX,
               dstRect->top + g_nQuickDrawOriginY, CRect(srcRect).Width(), CRect(srcRect).Height(),
               sourceDc.GetSafeHdc(), srcRect->left, srcRect->top, SRCCOPY);
      } else {
        destinationDc = g_pQuickDrawMemoryDc;
        if (destinationDc == 0) {
          destinationDc = g_pScopedMapQuickDrawDcHandleObject;
        }
        BitBlt(destinationDc->m_hDC, dstRect->left, dstRect->top, CRect(srcRect).Width(),
               CRect(srcRect).Height(), sourceDc.GetSafeHdc(), srcRect->left, srcRect->top,
               SRCCOPY);
      }

      if (previousBitmap != 0) {
        SelectObject(sourceDc.GetSafeHdc(), previousBitmap);
      }
    }
  } else {
    int srcPitch = srcSurface->stride;
    int dstPitch = dstSurface->stride;
    int rowCount = CRect(srcRect).Height();
    int rowBytes = CRect(srcRect).Width();
    if (rowCount < 0) {
      rowCount = -rowCount;
    }

    // The GDI branch clips off-screen rectangles for us. Memory-backed GWorlds need the
    // equivalent paired clipping before forming their pixel pointers: strategic-map hover
    // restoration can legitimately request a cached tile at (-32, -64), which otherwise
    // starts the destination copy before the DIB allocation.
    int srcX = srcRect->left;
    int srcY = srcRect->top;
    int dstX = dstRect->left;
    int dstY = dstRect->top;
    int trim = dstSurface->clipRect.left - dstX;
    if (trim > 0) {
      srcX += trim;
      dstX += trim;
      rowBytes -= trim;
    }
    trim = srcSurface->clipRect.left - srcX;
    if (trim > 0) {
      srcX += trim;
      dstX += trim;
      rowBytes -= trim;
    }
    if (dstX + rowBytes > dstSurface->clipRect.right) {
      rowBytes = dstSurface->clipRect.right - dstX;
    }
    if (srcX + rowBytes > srcSurface->clipRect.right) {
      rowBytes = srcSurface->clipRect.right - srcX;
    }

    trim = dstSurface->clipRect.top - dstY;
    if (trim > 0) {
      srcY += trim;
      dstY += trim;
      rowCount -= trim;
    }
    trim = srcSurface->clipRect.top - srcY;
    if (trim > 0) {
      srcY += trim;
      dstY += trim;
      rowCount -= trim;
    }
    if (dstY + rowCount > dstSurface->clipRect.bottom) {
      rowCount = dstSurface->clipRect.bottom - dstY;
    }
    if (srcY + rowCount > srcSurface->clipRect.bottom) {
      rowCount = srcSurface->clipRect.bottom - srcY;
    }
    if (rowBytes <= 0 || rowCount <= 0) {
      return;
    }

    unsigned char* srcPtr = srcSurface->pixelBits + srcY * srcPitch + srcX;
    unsigned char* dstPtr = dstSurface->pixelBits + dstY * dstPitch + dstX;
    if ((blitFlags & 0x24) != 0x24) {
      while (rowCount-- != 0) {
        memcpy(dstPtr, srcPtr, rowBytes);
        srcPtr += srcPitch;
        dstPtr += dstPitch;
      }
    } else {
      unsigned char transparentColor = static_cast<unsigned char>(g_QuickDrawBackgroundColor);
      int srcRowAdvance = srcPitch - rowBytes;
      int dstRowAdvance = dstPitch - rowBytes;
      while (rowCount-- != 0) {
        for (int count = rowBytes; count != 0; --count) {
          unsigned char srcPixel = *srcPtr++;
          if (srcPixel != transparentColor) {
            *dstPtr = srcPixel;
          }
          ++dstPtr;
        }
        srcPtr += srcRowAdvance;
        dstPtr += dstRowAdvance;
      }
    }
  }
  if (clipRegion != 0) {
    CDC* clipDc = g_pQuickDrawMemoryDc;
    if (clipDc == 0) {
      clipDc = g_pScopedMapQuickDrawDcHandleObject;
    }
    clipDc->SelectClipRgn(0);
  }
}

// FUNCTION: IMPERIALISM 0x00497c80
void SetQuickDrawTextOriginWithContextOffset(short x, short y) {
  if (!GetMcAppUiActiveFlag()) {
    return;
  }
  int resolvedX = x;
  int resolvedY = y;
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    resolvedX += g_nQuickDrawOriginX;
    resolvedY += g_nQuickDrawOriginY;
  }
  g_nQuickDrawResolvedTextOriginX = resolvedX;
  g_nQuickDrawResolvedTextOriginY = resolvedY;
  // Verified against 0x0057cc4-0x497cdd: no null guard on either DC in the original.
  // The nafxcw body at 0x6130a0 calls MoveToEx; its former OffsetWindowOrg identity was
  // a false FID attribution among several same-shaped CDC methods.
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->MoveTo(resolvedX, resolvedY);
}

// FUNCTION: IMPERIALISM 0x00497d10
void DrawCenteredGuideLineOnMapDc(short x, short y) {
  if (!GetMcAppUiActiveFlag()) {
    return;
  }
  int penWidth = g_nQuickDrawPenHorizontalSize;
  if (penWidth <= g_nQuickDrawPenVerticalSize) {
    penWidth = g_nQuickDrawPenVerticalSize;
  }
  CPen pen(PS_SOLID, penWidth, g_QuickDrawForegroundColor);

  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  CPen* oldPen = dc->SelectObject(&pen);

  // Verified against 0x0057db6-0x497e1b: this offsets the window origin using the
  // *stale* resolved-origin globals (left over from a previous
  // SetQuickDrawTextOriginWithContextOffset call) before recomputing them below --
  // faithful to the original's ordering, not a bug.
  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->MoveTo(g_nQuickDrawPenHorizontalSize / 2 + g_nQuickDrawResolvedTextOriginX,
             g_nQuickDrawPenVerticalSize / 2 + g_nQuickDrawResolvedTextOriginY);

  int resolvedX = x;
  int resolvedY = y;
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    resolvedX += g_nQuickDrawOriginX;
    resolvedY += g_nQuickDrawOriginY;
  }
  g_nQuickDrawResolvedTextOriginX = resolvedX;
  g_nQuickDrawResolvedTextOriginY = resolvedY;

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->LineTo(g_nQuickDrawPenHorizontalSize / 2 + resolvedX,
             g_nQuickDrawPenVerticalSize / 2 + resolvedY);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SelectObject(oldPen);
}

// FUNCTION: IMPERIALISM 0x00498980
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect) {
  CBrush brush;
  brush.CreateSolidBrush(g_QuickDrawForegroundColor);

  RECT fillRect;
  CopyRect(&fillRect, rect);

  CDib* activeSurfaceDib = 0;
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    activeSurfaceDib = 0;
  } else {
    TBitmapSurfaceContextDescriptor* descriptor =
        static_cast<TBitmapSurfaceContextDescriptor*>(g_pActiveQuickDrawSurfaceContextHead);
    TBitmapSurfaceNode* node = descriptor->GetPixMap();
    if (node != nullptr) {
      activeSurfaceDib = node->dib;
    }
  }
  if (activeSurfaceDib == 0) {
    OffsetRect(&fillRect, g_nQuickDrawOriginX, g_nQuickDrawOriginY);
  }

  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (dc != nullptr) {
    FillRect(dc->GetSafeHdc(), &fillRect, static_cast<HBRUSH>(brush.GetSafeHandle()));
  }
}

// FUNCTION: IMPERIALISM 0x00498b50
void __cdecl SetQuickDrawCursor(const QuickDrawCursor* cursor) {
  (void)cursor;
  if (g_QuickDrawSetCursorAssertGate == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szQuickDrawSourcePath_00695168, 0x984);
  }
}

// FUNCTION: IMPERIALISM 0x00498b80
QuickDrawCursorHandle __cdecl GetQuickDrawCursor(short cursorId) {
  (void)cursorId;
  if (g_QuickDrawGetCursorAssertGate == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szQuickDrawSourcePath_00695168, 0x988);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00498ca0
void HiliteColor(const RGBQUAD*) {}

// FUNCTION: IMPERIALISM 0x005d4c60
void TruncateTextToFitWidthWithEllipsis(CString* text, short maxWidth) {
  // Shrinks *text one character at a time, appending "...", until it (plus the
  // ellipsis) measures within maxWidth -- the reusable form of the loop
  // TMiniArmyView::Draw (0x4aaeb0) inlines by hand for its own name
  // label. Bails out to an empty string if truncation would leave fewer than 5
  // characters.
  if (MeasureTextExtentWithCachedQuickDrawStyle(text) > maxWidth) {
    CString truncated;
    do {
      truncated = text->Mid(0, text->GetLength() - 1);
      *text = truncated;
      truncated += "...";
    } while (MeasureTextExtentWithCachedQuickDrawStyle(&truncated) > maxWidth &&
             text->GetLength() > 4);
    if (text->GetLength() < 5) {
      *text = g_szEmptyString;
    }
    *text = truncated;
  }
}
