#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/gfx/TTemplateDialogs.h"

struct GlobalViewportRectDefaultsRecord {
  int field0;
  RECT viewportBounds;
};

extern "C" TBackdropWindow* g_pActiveBackdropWindow;

// Heap-owned MFC wait cursor kept alive while the startup backdrop is visible.
extern "C" CWaitCursor* g_pBackdropWaitCursor;

extern GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord;

extern GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord;

extern POINT g_ptSaveLoadErrorModalMessage;

extern int g_saveDocumentAssertGuard;

extern CString g_cstrUiFontBelweLight;

extern CString g_cstrUiFontPalatino;

extern CString g_cstrUiFontBelweBdBt;

// Process-lifetime trace dialog whose source-level global definition causes VC5 to emit
// the dynamic initializer at 0x0049baa0 and its registered cleanup at 0x0049bad0.
extern TD0TemplateDialog g_debugTraceDialog;

// File-scope zero geometry/color defaults recovered from the VC5 dynamic-initializer
// bodies in the 0x0049b9d0-0x0049cb60 cluster. They have no retail readers, but their
// real C++ types explain the compiler-emitted initializer shapes.
extern CRGBColor g_defaultRgbColor_006A1CE0;
extern CPoint g_defaultPoint_006A1CF8;
extern CRect g_defaultRect_006A1D30;
extern CRect g_defaultRect_006A1D68;
extern CPoint g_defaultPoint_006A1D78;
extern CRGBColor g_defaultRgbColor_006A1E18;
extern CPoint g_defaultPoint_006A1E20;
extern CRect g_defaultRect_006A1E28;
extern CRect g_defaultRect_006A1E38;
extern CPoint g_defaultPoint_006A1E48;
extern CRGBColor g_defaultRgbColor_006A1E68;
extern CPoint g_defaultPoint_006A1E70;
extern CRect g_defaultRect_006A1F18;
extern CRect g_defaultRect_006A1F28;
extern CPoint g_defaultPoint_006A1F38;
extern CRGBColor g_defaultRgbColor_006A1F70;
extern CPoint g_defaultPoint_006A1F78;
extern CRect g_defaultRect_006A1F88;
extern CRect g_defaultRect_006A1F98;
extern CPoint g_defaultPoint_006A1FA8;
extern double g_ScaleDefault6A1FC0;
extern CRGBColor g_defaultRgbColor_006A1FC8;
extern CPoint g_defaultPoint_006A1FD0;
extern CRect g_defaultRect_006A1FD8;
extern double g_ScaleDefault6A1FE8;
extern CRect g_defaultRect_006A1FF0;
extern CPoint g_defaultPoint_006A2000;
extern short g_scaledDefaultWidth_006A2008;
extern CPoint g_defaultPoint_006A2020;
extern CRGBColor g_defaultRgbColor_006A201C;
extern CRect g_defaultRect_006A2028;
extern CRect g_defaultRect_006A2038;
extern CPoint g_defaultPoint_006A2048;
extern CRGBColor g_defaultRgbColor_006A2068;
extern CPoint g_defaultPoint_006A2070;
extern CRect g_defaultRect_006A2078;
extern CRect g_defaultRect_006A2088;
extern CPoint g_defaultPoint_006A2098;
extern CRGBColor g_defaultRgbColor_006A20B0;
extern CPoint g_defaultPoint_006A20B8;
extern CRect g_defaultRect_006A20C0;
extern CRect g_defaultRect_006A20D0;
extern CPoint g_defaultPoint_006A20E0;
extern CPoint g_defaultPoint_006A2100;
extern double g_ScaleDefault6A2108;
extern CPoint g_defaultPoint_006A2118;
extern CPoint g_defaultPoint_006A2120;
extern double g_ScaleDefault6A2140;
extern CPoint g_defaultPoint_006A2150;
extern CPoint g_defaultPoint_006A2160;
extern CPoint g_defaultPoint_006A2198;
extern short g_scaledShortConst_6A21AC;
extern CPoint g_defaultPoint_006A21B0;

extern int g_paletteResourceNameAssertGate;
extern int g_paletteResourceIdAssertGate;

// Per-site assertion gate read by CDib::Compress before its CDib.cpp line-0x31b
// diagnostic call.
extern "C" {
extern int g_dibCompressAssertGate_006A1484;
extern double g_gfxScale6A14E0;
extern short g_scaledShortConst_6A1528;
extern double g_gfxScale6A1580;
extern short g_scaledShortConst_6A15C8;
extern const char g_szPaletteResourceType[];
extern const char g_szResourceMgrSourcePath[];
extern const char g_szPaletteResourceIdFormat[];
}

extern int g_nUiInvalidationAssertFlagLine471;

extern int g_nUiInvalidationAssertFlagLine495;

extern "C" {
// QuickDraw renderer state shared by the surface, clip, and text-drawing paths.
extern CRgn* g_pGlobalClipRegionHandleObject;
extern COLORREF g_QuickDrawForegroundColor;
extern char g_szQuickDrawFontFaceSystem[];
extern char g_szQuickDrawFontFaceBookAntiqua[];
extern char g_szQuickDrawFontFaceSmallFonts[];
extern int g_nQuickDrawOriginX;
extern int g_nQuickDrawOriginY;
extern TBitmapSurfaceContextDescriptor g_defaultQuickDrawSurfaceSentinel;
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext;
extern TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext;
extern CDC* g_pQuickDrawMemoryDc;
} // extern "C"

extern "C" {
extern const int g_nAmbitSaveFileMagic;

extern const int g_nCurrentAmbitSaveFormatVersion;

extern const char g_szUAmbitSourcePath[];

// Guards the nil-pointer assert in TColorFill::Draw (0x004ff1c0, TColorFill.cpp);
// no write site found anywhere in ported source, so this may be a debug/never-reached
// assertion path in the retail build rather than a genuine run-once flag.
extern int g_colorFillAssertGuard_006a30b4;

// QuickDraw OpenRgn/CloseRgn recording accumulator (QDFrameRect XORs framed rects into it).
extern HRGN g_hOpenRgnAccumulator;

extern int g_nDibOrientationFlag_006A1890;

// DiplomacyDialogs.cpp file-scope guard checked by the resource-A4 dialog's tail virtual.
// No writer is present in the retail image; zero takes the original diagnostic path.
extern int g_diplomacyDialogAssertGuard_006A15CC;

// One-slot CTemporaryRegion reuse cache (see CTemporaryRegion.h).
extern RgnHandle g_pTemporaryRegionCache;

// Provisional flag (0x00694c50) selecting the CDib blit path in TDDTemplateDialog::OnPaint.
extern int g_useCompatibleBitmapBlit;

extern "C" const char g_szDiplomacyDialogsSourcePath_00694CC0[];

// Source-file path string ("D:\\Ambit\\Cross\\UGameWindow.cpp") passed with a line number to
// the UI invalidation-flag assert helper from the TDlgWindow/UGameWindow assert hooks.
extern char g_szUGameWindowSourcePath_00696bc0[];

// Line-break characters the D0 trace dialog splits its pending text on ("\n\r").
// Defined inside the extern "C" block of global_data_tables.cpp, so declared with C
// linkage here to match.
extern char g_szTraceLineBreakChars_00695200[];

// UDisplayMgr font literals and runtime CString slots (markers in global_data_tables.cpp).
extern "C" const char g_szUiFontLiteralBelweBdBt[];

extern "C" const char g_szUiFontLiteralPalatino[];

extern "C" const char g_szUiFontLiteralBelweLight[];

} // extern "C"
