#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern GlobalViewportRectDefaultsRecord g_globalViewportRectDefaultsRecord;

extern GlobalViewportRectDefaultsRecord* g_pGlobalViewportRectDefaultsRecord;

extern POINT g_ptSaveLoadErrorModalMessage;

extern int g_saveDocumentAssertGuard;

extern CString g_cstrUiFontBelweLight;

extern CString g_cstrUiFontPalatino;

extern CString g_cstrUiFontBelweBdBt;

extern int g_nUiInvalidationAssertFlagLine471;

extern int g_nUiInvalidationAssertFlagLine495;

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

// One-slot CTemporaryRegion reuse cache (see CTemporaryRegion.h).
extern RgnHandle g_pTemporaryRegionCache;

// Provisional flag (0x00694c50) selecting the CDib blit path in TDDTemplateDialog::OnPaint.
extern int g_useCompatibleBitmapBlit;

// Source-file path string ("D:\\Ambit\\Cross\\UGameWindow.cpp") passed with a line number to
// the UI invalidation-flag assert helper from the TDlgWindow/UGameWindow assert hooks.
extern char g_szUGameWindowSourcePath_00696bc0[];

// UDisplayMgr font literals and runtime CString slots (markers in global_data_tables.cpp).
extern "C" const char g_szUiFontLiteralBelweBdBt[];

extern "C" const char g_szUiFontLiteralPalatino[];

extern "C" const char g_szUiFontLiteralBelweLight[];

} // extern "C"
