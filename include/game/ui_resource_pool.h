#pragma once

#include "game/TView.h"

// Shared helpers for the turn-event dialog factory builders (turn_event_dialog_factory.cpp
// and the per-screen builder functions). They operate on the global widget build stack
// (g_UiWidgetBuildStack006a13e0) and the g_pUiResourceHead/g_pUiResourceContext pair —
// see include/game/global_data_tables.h.

unsigned char* ZeroUiResourceContextStyleBytes(unsigned char* buffer);

// Out-of-line variant of the per-widget build prologue: push `widget` onto the build
// stack (parenting it to the previous stack tail), bind the frame/layout, and set the
// tag/enable/state values. `nameTag`/`ownerTag` are FourCC codes present at every call
// site but unused by the body (kept for signature fidelity).
void __cdecl RegisterUiResourceEntry(unsigned int nameTag, unsigned int controlTag, TView* widget,
                                     int offsetX, int offsetY, int width, int height,
                                     int stateValue, int enabledState, unsigned int ownerTag,
                                     int field3cValue);

// Set the frame-style dword (+0x60 hasCommandTagResource) and the 0x68-0x74 rect region
// on the current g_pUiResourceContext widget.
void __cdecl SetUiResourceLayoutValues(int frameStyle, int rectLeft, int rectTop, int rectRight,
                                       int rectBottom);

// Set the flag4c/flag4d pair on the current g_pUiResourceContext widget.
void __cdecl SetUiResourceStateFlags(unsigned char flag4c, unsigned char flag4d);

// Assign text + packed style descriptor + theme code onto the current
// g_pUiResourceContext text control (a TStaticText-family widget).
void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, char* szText, short nMode,
                                        short nFlag, short nPointSize, int styleRef,
                                        short nThemeCode);
