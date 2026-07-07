#include "game/quickdraw_rendering.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TStaticText.h"
#include <cstring>

// FUNCTION: IMPERIALISM 0x00494130
CFont* __cdecl CreateFontFromPresetAndAttachRegionHandle(TControlPictureRectState* preset) {
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
  if (preset->pointSize != 0) {
    sizeIndex = preset->pointSize;
  }
  int family = preset->mode;
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
  if ((preset->flag2 & 1) != 0) {
    logFont.lfWeight = 700;
  }
  logFont.lfItalic = static_cast<unsigned char>(preset->flag2 & 2);
  logFont.lfUnderline = static_cast<unsigned char>(preset->flag2 & 4);
  font->Attach(CreateFontIndirectA(&logFont));
  return font;
}

// FUNCTION: IMPERIALISM 0x004944e0
CFont* __cdecl UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(TControlPictureRectState* style) {
  if (g_QuickDrawCachedFontPreset.mode != style->mode) {
    g_bQuickDrawCachedFontDirty = 1;
    g_QuickDrawCachedFontPreset.mode = style->mode;
  }
  if (g_QuickDrawCachedFontPreset.flag2 != style->flag2) {
    g_bQuickDrawCachedFontDirty = 1;
    g_QuickDrawCachedFontPreset.flag2 = style->flag2;
  }
  if (g_QuickDrawCachedFontPreset.pointSize != style->pointSize) {
    g_bQuickDrawCachedFontDirty = 1;
    g_QuickDrawCachedFontPreset.pointSize = style->pointSize;
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
  dc->SetTextColor(static_cast<COLORREF>(g_QuickDrawMeasureFontPreset.styleRef6));

  dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
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
  g_QuickDrawMeasureFontPreset.styleRef6 = fillColor;
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
  g_QuickDrawMeasureFontPreset.styleRef6 = color;
}

// FUNCTION: IMPERIALISM 0x004950d0
void SetGlobalBlitTransparentColorRaw(int transparentColor) {
  g_uQuickDrawStrokeColor = transparentColor;
}

// FUNCTION: IMPERIALISM 0x00495230
void SetQuickDrawTextFont(short value) {
  if (g_QuickDrawMeasureFontPreset.mode != value) {
    g_QuickDrawMeasureFontPreset.mode = value;
    g_bQuickDrawMeasureFontDirty = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00495260
void SetQuickDrawTextSize(short value) {
  if (g_QuickDrawMeasureFontPreset.pointSize != value) {
    g_QuickDrawMeasureFontPreset.pointSize = value;
    g_bQuickDrawMeasureFontDirty = 1;
  }
}

// FUNCTION: IMPERIALISM 0x00495290
void SetQuickDrawTextFace(short value) {
  if (g_QuickDrawMeasureFontPreset.flag2 != value) {
    g_QuickDrawMeasureFontPreset.flag2 = value;
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

// FUNCTION: IMPERIALISM 0x005c3d20
void MapUiThemeCodeToStyleFlags(short themeCode, int* outStyleFlags) {
  switch (themeCode) {
  case 0x2b67:
    *outStyleFlags = 0x1000000;
    return;
  case 0x2b68:
    *outStyleFlags = 0x1000013;
    return;
  case 0x2b6a:
    *outStyleFlags = 0x100005c;
    return;
  case 0x2b6b:
    *outStyleFlags = 0x10000d2;
    return;
  case 0x2b69:
    *outStyleFlags = 0x10000cb;
    return;
  case 0x2b6c:
    *outStyleFlags = 0x1000028;
    return;
  case 0x2b6d:
    *outStyleFlags = 0x1000001;
    return;
  case 0x2b6e:
    *outStyleFlags = 0x1000001;
    return;
  case 0x2b6f:
    *outStyleFlags = 0x100002a;
    return;
  case 0x2b70:
    *outStyleFlags = 0x10000c9;
    return;
  case 0x2b71:
    *outStyleFlags = 0x100001b;
    return;
  case 0x2b72:
    *outStyleFlags = 0x1000030;
    return;
  case 0x2b73:
    *outStyleFlags = 0x10000c8;
    return;
  case 0x2b74:
    *outStyleFlags = 0x10000e3;
    return;
  default:
    *outStyleFlags = (themeCode & 0xffff) | 0x1000000;
    return;
  }
}

// FUNCTION: IMPERIALISM 0x005c3e80
void BuildUiTextStyleDescriptor(void* styleDescriptor, int unused, int arg2, int themeCode) {
  (void)unused;
  // Verified against 0x5c3e9b-0x5c3f01: constructed unconditionally, never read or
  // written again -- a genuinely dead local kept faithfully (not our porting
  // artifact; the original does the same).
  CString deadLocal;
  short* fields = static_cast<short*>(styleDescriptor);
  fields[1] = 0;
  int styleFlags = 0;
  MapUiThemeCodeToStyleFlags(static_cast<short>(themeCode), &styleFlags);
  *reinterpret_cast<int*>(fields + 3) = styleFlags;
  fields[2] = static_cast<short>(arg2);
  fields[0] = (arg2 >= 0xc) ? 1 : 3;
}

// FUNCTION: IMPERIALISM 0x005c3f50
void InitializeUiTextStyleDescriptor(TControlPictureRectState* styleDescriptor, short face,
                                     short pointSize, int themeCode, short font) {
  // Same dead CString shape as BuildUiTextStyleDescriptor; the original constructs and
  // destroys it while only using the packed descriptor fields below.
  CString deadLocal;
  int styleFlags = 0;
  styleDescriptor->flag2 = face;
  MapUiThemeCodeToStyleFlags(static_cast<short>(themeCode), &styleFlags);
  styleDescriptor->pointSize = pointSize;
  styleDescriptor->styleRef6 = styleFlags;
  styleDescriptor->mode = font;
}

// FUNCTION: IMPERIALISM 0x005c4020
TStaticText* ApplyControlThemeStyleAndOptionalCaption(TStaticText* control, int unused2,
                                                      int pointSize, int themeCode, int themeCode2,
                                                      const char* caption) {
  (void)unused2;
  control->AssertValid();
  TControlPictureRectState styleDescriptor;
  styleDescriptor.mode = 0;
  styleDescriptor.flag2 = 0;
  styleDescriptor.pointSize = 0;
  styleDescriptor.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, pointSize, themeCode);
  control->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
  control->SetTextThemeCodeAndMaybeRefresh(static_cast<short>(themeCode2), 0);
  if (caption != 0) {
    CString captionString(caption);
    control->AssignTextSharedRefIfChangedAndMaybeInvalidate(&captionString, 0);
  }
  return control;
}

// FUNCTION: IMPERIALISM 0x005c4470
void ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(int unused, int styleWidth, int themeCode) {
  TControlPictureRectState styleDescriptor;
  styleDescriptor.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, unused, styleWidth, themeCode);
  SetQuickDrawTextFace(styleDescriptor.flag2);
  SetQuickDrawTextSize(styleDescriptor.pointSize);
  SetQuickDrawTextFont(styleDescriptor.mode);
  SetQuickDrawColorAndSyncGlobals(styleDescriptor.styleRef6);
}

// FUNCTION: IMPERIALISM 0x005c4500
void InitializeUiTextStyleDescriptorAndApplyQuickDraw(short face, short pointSize, int themeCode,
                                                      short font) {
  TControlPictureRectState styleDescriptor;
  styleDescriptor.styleRef6 = 0;
  InitializeUiTextStyleDescriptor(&styleDescriptor, face, pointSize, themeCode, font);
  SetQuickDrawTextFace(styleDescriptor.flag2);
  SetQuickDrawTextSize(styleDescriptor.pointSize);
  SetQuickDrawTextFont(styleDescriptor.mode);
  SetQuickDrawColorAndSyncGlobals(styleDescriptor.styleRef6);
}
