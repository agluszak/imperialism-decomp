#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/gfx/TTemplateDialogs.h"

class TDisplayMgr;

extern TDisplayMgr* g_pDisplayMgr;

struct GlobalViewportRectDefaultsRecord {
  int field0;
  RECT viewportBounds;
};

extern "C" TBackdropWindow* g_pActiveBackdropWindow;
extern "C" TAmbitApplication* g_pAmbitApplication;
extern "C" TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;

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
extern double g_gfxCoordinateScale_6A12F8;
extern short g_scaledShortConst_6A1340;
extern double g_gfxCoordinateScale_6A13A8;
extern short g_scaledShortConst_6A1418;
extern double g_gfxCoordinateScale_6A1638;
extern short g_scaledShortConst_6A1680;
extern double g_gfxCoordinateScale_6A1690;
extern short g_scaledShortConst_6A16D8;
extern double g_gfxCoordinateScale_6A1730;
extern short g_scaledShortConst_6A177C;
extern double g_gfxCoordinateScale_6A17E8;
extern short g_scaledShortConst_6A1830;
extern double g_gfxCoordinateScale_6A18F0;
extern short g_scaledShortConst_6A1938;
extern double g_gfxCoordinateScale_6A1A30;
extern short g_scaledShortConst_6A1AB8;
extern double g_gfxCoordinateScale_6A1BF0;
extern short g_scaledShortConst_6A1C38;
extern double g_gfxCoordinateScale_6A1CD8;
extern short g_scaledShortConst_6A1D88;
extern double g_gfxCoordinateScale_6A21F8;
extern short g_scaledShortConst_6A2248;
extern double g_gfxCoordinateScale_6A2268;
extern short g_scaledShortConst_6A22D8;
extern double g_gfxCoordinateScale_6A2308;
extern short g_scaledShortConst_6A2350;
extern double g_gfxCoordinateScale_6A2360;
extern short g_scaledShortConst_6A23B0;
extern double g_gfxCoordinateScale_6A23D0;
extern short g_scaledShortConst_6A2418;
extern double g_gfxCoordinateScale_6A2428;
extern short g_scaledShortConst_6A2470;
extern double g_gfxCoordinateScale_6A2488;
extern short g_scaledShortConst_6A24D0;
extern double g_gfxCoordinateScale_6A2968;
extern short g_scaledShortConst_6A2AB8;
extern double g_gfxCoordinateScale_6A2BF8;
extern short g_scaledShortConst_6A2C60;
extern double g_gfxCoordinateScale_6A2C98;
extern short g_scaledShortConst_6A2D00;
extern double g_gfxCoordinateScale_6A2D30;
extern short g_scaledShortConst_6A2D80;
extern double g_gfxCoordinateScale_6A2DE0;
extern short g_scaledShortConst_6A2E28;
extern double g_gfxCoordinateScale_6A2E38;
extern short g_scaledShortConst_6A2E80;
extern double g_gfxCoordinateScale_6A2E90;
extern short g_scaledShortConst_6A2EE8;
extern double g_gfxCoordinateScale_6A2F00;
extern short g_scaledShortConst_6A2F48;
extern double g_gfxCoordinateScale_6A2F58;
extern short g_scaledShortConst_6A2FA0;
extern double g_gfxCoordinateScale_6A2FB0;
extern short g_scaledShortConst_6A3018;
extern double g_gfxCoordinateScale_6A3048;
extern short g_scaledShortConst_6A30A0;
extern double g_gfxCoordinateScale_6A3118;
extern short g_scaledShortConst_6A3160;
extern double g_gfxCoordinateScale_6A3170;
extern short g_scaledShortConst_6A31B8;
extern double g_gfxCoordinateScale_6A31D8;
extern short g_scaledShortConst_6A3220;
extern double g_gfxCoordinateScale_6A3230;
extern short g_scaledShortConst_6A3278;
extern double g_gfxCoordinateScale_6A3290;
extern short g_scaledShortConst_6A32E0;
extern double g_gfxCoordinateScale_6A3488;
extern short g_scaledShortConst_6A38F4;
extern double g_gfxCoordinateScale_6A3A08;
extern short g_scaledShortConst_6A3A50;
extern double g_gfxCoordinateScale_6A3A78;
extern short g_scaledShortConst_6A3B80;
extern double g_gfxCoordinateScale_6A3BF8;
extern short g_scaledShortConst_6A3C64;
extern double g_gfxCoordinateScale_6A3C88;
extern short g_scaledShortConst_6A3CD0;
extern double g_gfxCoordinateScale_6A3CE8;
extern short g_scaledShortConst_6A3D50;
extern double g_gfxCoordinateScale_6A3D88;
extern short g_scaledShortConst_6A3DD0;
extern double g_gfxCoordinateScale_6A3DE8;
extern short g_scaledShortConst_6A3EB8;
extern double g_gfxCoordinateScale_6A3F18;
extern short g_scaledShortConst_6A3F60;
extern double g_gfxCoordinateScale_6A3F70;
extern short g_scaledShortConst_6A3FB8;
extern double g_gfxCoordinateScale_6A3FE0;
extern short g_scaledShortConst_6A4028;
extern double g_gfxCoordinateScale_6A4038;
extern short g_scaledShortConst_6A4080;
extern double g_gfxCoordinateScale_6A4098;
extern short g_scaledShortConst_6A40E0;
extern double g_gfxCoordinateScale_6A40F0;
extern short g_scaledShortConst_6A4138;
extern double g_gfxCoordinateScale_6A4148;
extern short g_scaledShortConst_6A4190;
extern double g_gfxCoordinateScale_6A41B0;
extern short g_scaledShortConst_6A41F8;
extern double g_gfxCoordinateScale_6A4208;
extern short g_scaledShortConst_6A4260;
extern double g_gfxCoordinateScale_6A42E0;
extern short g_scaledShortConst_6A43BC;
extern double g_gfxCoordinateScale_6A4440;
extern short g_scaledShortConst_6A4488;
extern double g_gfxCoordinateScale_6A44D0;
extern short g_scaledShortConst_6A4518;
extern double g_gfxCoordinateScale_6A4538;
extern short g_scaledShortConst_6A4580;
extern double g_gfxCoordinateScale_6A4630;
extern short g_scaledShortConst_6A46A0;
extern double g_gfxCoordinateScale_6A46D8;
extern short g_scaledShortConst_6A4748;
extern double g_gfxCoordinateScale_6A5438;
extern short g_scaledShortConst_6A54A8;
extern double g_gfxCoordinateScale_6A5760;
extern short g_scaledShortConst_6A57A8;
extern double g_gfxCoordinateScale_6A57B8;
extern short g_scaledShortConst_6A5800;
extern double g_gfxCoordinateScale_6A5810;
extern short g_scaledShortConst_6A5858;
extern double g_gfxCoordinateScale_6A5868;
extern short g_scaledShortConst_6A58B0;
extern double g_gfxCoordinateScale_6A58C0;
extern short g_scaledShortConst_6A5908;
extern double g_gfxCoordinateScale_6A5920;
extern short g_scaledShortConst_6A5968;
extern double g_gfxCoordinateScale_6A5978;
extern short g_scaledShortConst_6A59C0;
extern double g_gfxCoordinateScale_6A59D0;
extern short g_scaledShortConst_6A5A20;
extern double g_gfxCoordinateScale_6A5A48;
extern short g_scaledShortConst_6A5A90;
extern double g_gfxCoordinateScale_6A5AA0;
extern short g_scaledShortConst_6A5AE8;
extern double g_gfxCoordinateScale_6A5B48;
extern short g_scaledShortConst_6A5BA8;
extern double g_gfxCoordinateScale_6A5BD0;
extern short g_scaledShortConst_6A5C18;
extern double g_gfxCoordinateScale_6A5C28;
extern short g_scaledShortConst_6A5C70;
extern double g_gfxCoordinateScale_6A5C80;
extern short g_scaledShortConst_6A5CF0;
extern double g_gfxCoordinateScale_6A5DE0;
extern short g_scaledShortConst_6A5E28;
extern double g_gfxCoordinateScale_6A5EC8;
extern short g_scaledShortConst_6A5F3C;
extern double g_gfxCoordinateScale_6A6070;
extern short g_scaledShortConst_6A60B8;
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

// Selects the CDib blit path in TDDTemplateDialog::OnPaint (0x00694c50).
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
