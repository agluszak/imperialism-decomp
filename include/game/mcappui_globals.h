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

// Source-file path string ("D:\\Ambit\\McAppUI.cpp") passed with a line number to the
// UI invalidation-flag assert/log helper.
extern char g_szMcAppUiSourcePath_006950B0[];

} // extern "C"
