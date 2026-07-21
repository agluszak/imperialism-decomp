#pragma once

#include "game/TView.h"

// Global-state UI resource/widget builder (was misnamed "ui_resource_pool"): the
// push-widget / attach-to-stack-tail / configure-layout+tags+state / clear-context
// vocabulary used by the turn-event dialog factory (turn_event_dialog_factory.cpp) and the
// per-screen builder functions. Operates on the global widget build stack
// (g_UiWidgetBuildStack006a13e0) and the g_pUiResourceHead/g_pUiResourceContext pair — see
// include/game/global_data_tables.h. It is a builder, not a pool.

// 4-byte by-value style-ref wrapper (bd 1uj.51.2): constructed in place on the stack as
// BindUiResourceTextAndStyle's styleRef argument. Factory-builder call sites convert an
// int through the out-of-line converting ctor 0x4270e0 (~200 calls across the cluster);
// sites passing an existing TUiStyleRef copy it trivially (plain push, no call).
class TUiStyleRef {
public:
  TUiStyleRef(int value); // 0x4270e0
  int value;
};

// Out-of-line variant of the per-widget build prologue: push `widget` onto the build
// stack (parenting it to the previous stack tail), bind the frame/layout, and set the
// tag/enable/state values. `nameTag`/`ownerTag` are FourCC codes present at every call
// site but unused by the body (kept for signature fidelity).
void __cdecl RegisterUiResourceEntry(unsigned int nameTag, unsigned int controlTag, TView* widget,
                                     int offsetX, int offsetY, int width, int height,
                                     int stateValue, int enabledState, unsigned int ownerTag,
                                     int field3cValue);

// Set the frame-style dword (+0x60 frameStyle60) and the 0x68-0x74 rect region
// on the current g_pUiResourceContext widget.
void __cdecl SetUiResourceLayoutValues(int frameStyle, int rectLeft, int rectTop, int rectRight,
                                       int rectBottom);

// Set the inputGateFlag4c/childHitTestFlag4d pair on the current g_pUiResourceContext widget.
void __cdecl SetUiResourceStateFlags(bool inputGateFlag4c, bool childHitTestFlag4d);

// Assign text + packed style descriptor + theme code onto the current
// g_pUiResourceContext text control (a TStaticText-family widget).
void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, const char* szText, short nMode,
                                        short nFlag, short nPointSize, TUiStyleRef styleRef,
                                        short nThemeCode);

// Set the current context edit control's max-character-count word (+0x9c).
void __cdecl SetUiResourceContextMaxCharCount(short maxChars);

// Set the picture resource id on the current g_pUiResourceContext picture widget
// (virtual slot 0x72 SetPictureResourceIdAndRefresh, no immediate refresh).
void __cdecl SetUiResourceContextPictureId(int nPictureId);

// Store a FourCC group/mode code as the current context cluster's selected child tag.
void __cdecl SetUiResourceContextStringCode(int nCode);

// Replace the current context widget's stylePayload48 style payload with a fresh zeroed
// buffer carrying {packedColor, styleWord}.
void __cdecl ReplaceUiResourceContextPairBuffer(int styleWord, int packedColor);

// Set the TWindow style/flag block (+0x6c..+0x71 flags, +0x9c mode word, +0x60 window
// style type) on the current context window.
void __cdecl SetUiResourceContextFlagsAndMetrics(short nField9C, short nStyleType, bool f70,
                                                 bool f6f, bool f6e, bool f6d, bool f6c, bool f71);

// Set the embedded dialog behavior's flag0C and gold color triplet on the current
// context window.
void __cdecl ApplyUiResourceColorTripletFromContext(unsigned char nFlag0C,
                                                    unsigned char nTripletFlag, int colorA,
                                                    int colorB);

// Bind the value range (TNumberText::minimumValue/maximumValue) and the
// current value (virtual slot 0x79 SetControlValue, no immediate refresh) on the
// current context number-text widget.
void __cdecl SetUiResourceContextNumberValueAndRange(int value, int minValue, int maxValue);

// Clear the g_pUiResourceContext cursor.
void __cdecl ClearUiResourceContext();

// Pop the top build-stack node; when the stack empties, release the node pool.
// `nameTag` is the FourCC of the widget being closed — present at every call site but
// unused by the body (signature fidelity, like RegisterUiResourceEntry's tags).
void __cdecl PopUiResourcePoolNode(unsigned int nameTag);
