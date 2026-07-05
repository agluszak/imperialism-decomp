#include "game/quickdraw_rendering.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TStaticText.h"

// FUNCTION: IMPERIALISM 0x00495000
void SetQuickDrawFillColor(int fillColor) {
  g_Quick_Draw_Color_State_006950FC = fillColor;
  if (g_pActiveQuickDrawSurfaceContext != 0) {
    g_pActiveQuickDrawSurfaceContext->quickDrawColor = fillColor;
  }
  g_uQuickDrawCurrentColor = fillColor;
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
  g_uQuickDrawCurrentColor = color;
}

// FUNCTION: IMPERIALISM 0x004950d0
void SetGlobalBlitTransparentColorRaw(int transparentColor) {
  g_uQuickDrawStrokeColor = transparentColor;
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
