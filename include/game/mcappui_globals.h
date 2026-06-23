#pragma once

#include "decomp_types.h"

// Module-level globals from the original McAppUI.cpp translation unit, referenced by
// TView/TControl widget code. reccmp pairs these by the config/symbols.csv address map
// (the recompiled values are irrelevant — only symbol identity and use site matter).
// Names are address-anchored because the exact semantics are only partially recovered.

extern "C" {

// Gate checked before touching a control's native window (e.g. ValidateRect /
// InvalidateRect): non-zero once the UI subsystem/screen is realized.
extern int g_McAppUiActiveFlag_006950AC;

// Gate checked in the QuickDraw/GDI draw path before temporarily clearing the UI
// invalidation flag.
extern int g_McAppUiDrawGate_006A1AF8;

// Gate checked before the invalidation-flag assert/log call in the child-detach path.
extern int g_McAppUiFlag_006A1AE0;

// Gate checked before the UI resource-entry allocation assert in TEventHandler slot 0x08.
extern int g_McAppUiFlag_006A1AE4;

// Further invalidation-flag assert gates (McAppUI.cpp lines 1914 / 1922).
extern int g_McAppUiFlag_006A1AFC;
extern int g_McAppUiFlag_006A1B00;

// Per-line one-shot invalidation-flag assert gates used by TWindow's UI slot bodies.
extern int g_McAppUiFlag_006A1B04;
extern int g_McAppUiFlag_006A1B08;
extern int g_McAppUiFlag_006A1B10;
extern int g_McAppUiFlag_006A1B14;
extern int g_McAppUiFlag_006A1B18;
extern int g_McAppUiFlag_006A1B1C;

// Reentrancy guard for the root UpdateWindow pass driven by TView slot 0x4f.
extern int g_McAppUiUpdateWindowRecursionGuard_006A1AF0;

// Active QuickDraw origin/render context view for slot 0x3e.
extern class TView* g_McAppUiActiveRenderContext_006A1AF4;

// Default absolute layout position (x, y) used when a control has no owner context, in
// the position-propagation pass (TView::vmethod_0089).
extern int g_McAppUiDefaultPosX_006A1A60;
extern int g_McAppUiDefaultPosY_006A1A64;

// Mouse-capture drag/repeat state used by TControl's input slots.
extern int g_McAppUiMouseCaptureStartPoint_006A1A68[2];
extern int g_McAppUiMouseCaptureLastPoint_006A1A70[2];
extern int g_McAppUiMouseCaptureCurrentPoint_006A1A78[2];
extern class TControl* g_McAppUiMouseCaptureControl_006A1A80;
extern unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC;

// Source-file path string ("D:\\Ambit\\McAppUI.cpp") passed with a line number to the
// UI invalidation-flag assert/log helper.
extern char g_szMcAppUiSourcePath_006950B0[];

// Header path string ("D:\\Ambit\\McAppUI.h") passed with a line number to city-production
// dialog assert/log helpers on the TControl branch.
extern char g_szMcAppUiHeaderPath_006943CC[];

// Gate checked by TControl::AssertCityProductionGlobalStateInitialized before the
// McAppUI.h line-0x56f assert path runs.
extern int g_McAppUiFlag_006A143C;

} // extern "C"
