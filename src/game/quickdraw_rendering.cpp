#include "game/quickdraw_rendering.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TStaticText.h"
#include <cstring>

// FUNCTION: IMPERIALISM 0x00494130
CFont* __cdecl CreateFontFromPresetAndAttachRegionHandle(TUiTextStyleDescriptor* preset) {
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
CFont* __cdecl UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(TUiTextStyleDescriptor* style) {
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
  dc->SetBkMode(TRANSPARENT);

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
// flags. Only called by TTradeScreenPicture::ApplyRectSlot110.
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
void SetQuickDrawFillColor(int fillColor) {
  g_Quick_Draw_Color_State_006950FC = fillColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->quickDrawColor = fillColor;
  }
  g_QuickDrawMeasureFontPreset.textColor = fillColor;
}

// Sets the current QuickDraw draw color, propagating it to the active surface context and the
// cached measure-font style ref, but only when it actually changed.
// FUNCTION: IMPERIALISM 0x00495030
void SetQuickDrawColorAndPropagateIfChanged(int newColor) {
  if (g_Quick_Draw_Color_State_006950FC != newColor) {
    g_Quick_Draw_Color_State_006950FC = newColor;
    g_pActiveQuickDrawSurfaceContext->quickDrawColor = newColor;
    g_QuickDrawMeasureFontPreset.textColor = newColor;
  }
}

// FUNCTION: IMPERIALISM 0x00495070
void SetQuickDrawStrokeColor(int strokeColor) {
  g_uQuickDrawStrokeColor = strokeColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->transparentBlitColor = strokeColor;
  }
}

// FUNCTION: IMPERIALISM 0x004950a0
void SetQuickDrawColorAndSyncGlobals(int color) {
  g_Quick_Draw_Color_State_006950FC = color;
  g_pActiveQuickDrawSurfaceContext->quickDrawColor = color;
  g_QuickDrawMeasureFontPreset.textColor = color;
}

// FUNCTION: IMPERIALISM 0x004950d0
void SetGlobalBlitTransparentColorRaw(int transparentColor) {
  g_uQuickDrawStrokeColor = transparentColor;
}

// FUNCTION: IMPERIALISM 0x004950f0
void SetQuickDrawFillColorFromPaletteIndex(unsigned short paletteIndex) {
  if (g_pQuickDrawMemoryDc != nullptr) {
    // TODO(class-recovery): resolves the real color from TMacViewMgr's resource-cache
    // palette handle via GetPaletteEntries; same unresolved thunk as
    // UpdatePaletteIndexWithDefaultFallback's -1 fallback. Left unmodeled.
    return;
  }
  if (paletteIndex == 0xff) {
    SetQuickDrawFillColor(0);
  } else if (static_cast<short>(paletteIndex) < 1) {
    SetQuickDrawFillColor(0xffffff);
  } else {
    SetQuickDrawFillColor(paletteIndex | 0x1000000);
  }
}

// FUNCTION: IMPERIALISM 0x004951e0
void UpdatePaletteIndexWithDefaultFallback(unsigned int paletteIndex) {
  if ((short)paletteIndex == -1) {
    // TODO(class-recovery): the original resolves this from the default cached
    // bitmap resource (id 0x3b6) via a TMacViewMgr-owned refcounted resource cache
    // (TMacViewMgr::ResolveBmpResourceHandleWithDefault3B6, 0x004995c0) and reads
    // GetNearestPaletteIndex(cacheNode->hPalette, 0xffffff) from it. That cache's
    // node layout isn't recovered yet, so the fallback itself isn't modeled. Every
    // current caller passes a real index (0x10/0x13), never -1.
  }
  g_uQuickDrawStrokeColor = (paletteIndex & 0xffff) | 0x1000000;
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

// TODO(shortcut): the real owner is a static-init object at 0x6a1d58 whose ctor
// (0x494040, CRT init table) does `g_pGlobalClipRegionHandleObject = new CRgn;
// ...->Attach(::CreateRectRgn(0,0,0,0));` and also seeds its own +0x8 field with
// &g_defaultQuickDrawSurfaceSentinel. That object isn't modeled yet, so the CRgn is
// created lazily here instead; same object shape (a real heap CRgn), different
// construction time. SetClip/GetClip (quickdraw_regions.cpp) read the same global.
CRgn* EnsureGlobalClipRegionHandleObject() {
  if (g_pGlobalClipRegionHandleObject == 0) {
    g_pGlobalClipRegionHandleObject = new CRgn;
    g_pGlobalClipRegionHandleObject->Attach(::CreateRectRgn(0, 0, 0, 0));
  }
  return g_pGlobalClipRegionHandleObject;
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
void __stdcall BlitRectWithOptionalTransparency(TQuickDrawBlitSurface* srcSurface,
                                                TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                                RECT* dstRect, unsigned char blitFlags,
                                                void* renderCtx) {
  if (dstSurface == g_defaultQuickDrawSurfaceSentinel.GetBlitSurface() || renderCtx != nullptr) {
    // TODO(class-recovery): GDI/CDC path -- draws straight to the real screen surface
    // (or through a caller-supplied clip region) via CreateCompatibleDC/BitBlt (or
    // StretchDIBits for the blitFlags&0x24 case). Not modeled: renderCtx's real type
    // is unrecovered and every current caller (all via BlitQuickDrawSurfaces) passes
    // dstSurface != the screen sentinel and renderCtx == null, so this path is dead
    // for all current call sites.
  } else {
    int rowCount = srcRect->bottom - srcRect->top;
    if (rowCount < 0) {
      rowCount = -rowCount;
    }
    int rowBytes = srcRect->right - srcRect->left;
    int srcPitch = srcSurface->stride;
    int dstPitch = dstSurface->stride;
    char* srcPtr =
        static_cast<char*>(srcSurface->pixelBits) + srcRect->top * srcPitch + srcRect->left;
    char* dstPtr =
        static_cast<char*>(dstSurface->pixelBits) + dstRect->top * dstPitch + dstRect->left;
    if ((blitFlags & 0x24) == 0x24) {
      char transparentColor = static_cast<char>(g_uQuickDrawStrokeColor);
      for (; rowCount != 0; --rowCount) {
        for (int count = rowBytes; count != 0; --count) {
          char srcPixel = *srcPtr++;
          if (srcPixel != transparentColor) {
            *dstPtr = srcPixel;
          }
          ++dstPtr;
        }
        srcPtr += srcPitch - rowBytes;
        dstPtr += dstPitch - rowBytes;
      }
    } else {
      for (; rowCount != 0; --rowCount) {
        char* rowSrcPtr = srcPtr;
        char* rowDstPtr = dstPtr;
        for (int dwordCount = rowBytes >> 2; dwordCount != 0; --dwordCount) {
          *reinterpret_cast<unsigned int*>(rowDstPtr) = *reinterpret_cast<unsigned int*>(rowSrcPtr);
          rowSrcPtr += 4;
          rowDstPtr += 4;
        }
        for (int byteCount = rowBytes & 3; byteCount != 0; --byteCount) {
          *rowDstPtr++ = *rowSrcPtr++;
        }
        srcPtr += srcPitch;
        dstPtr += dstPitch;
      }
    }
  }
  if (renderCtx != nullptr) {
    CDC* dc = g_pQuickDrawMemoryDc;
    if (dc == nullptr) {
      dc = g_pScopedMapQuickDrawDcHandleObject;
    }
    dc->SelectClipRgn(0);
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
  // Verified against 0x0057cc4-0x497cdd: no null guard on either DC in the original --
  // OffsetWindowOrg is called unconditionally, even on a null `dc` (matches faithfully).
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->OffsetWindowOrg(resolvedX, resolvedY);
}

// FUNCTION: IMPERIALISM 0x00497d10
void DrawCenteredGuideLineOnMapDc(short x, short y) {
  if (!GetMcAppUiActiveFlag()) {
    return;
  }
  int penWidth = g_nQuickDrawStrokeStylePrimary;
  if (penWidth <= g_nQuickDrawStrokeStyleSecondary) {
    penWidth = g_nQuickDrawStrokeStyleSecondary;
  }
  CPen pen(PS_SOLID, penWidth, static_cast<COLORREF>(g_Quick_Draw_Color_State_006950FC));

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
  dc->OffsetWindowOrg(g_nQuickDrawStrokeStylePrimary / 2 + g_nQuickDrawResolvedTextOriginX,
                      g_nQuickDrawStrokeStyleSecondary / 2 + g_nQuickDrawResolvedTextOriginY);

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
  dc->LineTo(g_nQuickDrawStrokeStylePrimary / 2 + resolvedX,
             g_nQuickDrawStrokeStyleSecondary / 2 + resolvedY);

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SelectObject(oldPen);
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
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (dc != nullptr) {
    FillRect(dc->GetSafeHdc(), &fillRect, static_cast<HBRUSH>(brush.GetSafeHandle()));
  }
}

// FUNCTION: IMPERIALISM 0x005d4c60
void TruncateTextToFitWidthWithEllipsis(CString* text, short maxWidth) {
  // Shrinks *text one character at a time, appending "...", until it (plus the
  // ellipsis) measures within maxWidth -- the reusable form of the loop
  // TMiniArmyView::ApplyRectSlot110 (0x4aaeb0) inlines by hand for its own name
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
