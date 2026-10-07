#pragma once

#include "game/ui_core/TView.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
void RuntimeTestObserveBuiltUiTree(int eventCode, TView* root);
#endif

// Global-state UI resource/widget builder (was misnamed "ui_resource_pool"): the
// push-widget / attach-to-stack-tail / configure-layout+tags+state / clear-context
// vocabulary used by the turn-event dialog factory (turn_event_dialog_factory.cpp) and the
// per-screen builder functions. Operates on the global widget build stack
// (g_UiWidgetBuildStack) and the g_pUiResourceHead/g_pUiResourceContext pair — see
// include/game/global_data_tables.h. It is a builder, not a pool.

class TUiStyleRef {
public:
  TUiStyleRef(int value); // 0x4270e0
  int value;
};

void __cdecl RegisterUiResourceEntry(unsigned int nameTag, unsigned int controlTag, TView* widget,
                                     int offsetX, int offsetY, int width, int height,
                                     int stateValue, int enabledState, unsigned int ownerTag,
                                     int field3cValue);

void __cdecl SetUiResourceEventNumberAndInsets(int eventNumber, int rectLeft, int rectTop,
                                               int rectRight, int rectBottom);

// Set the inputGateFlag/childHitTestFlag pair on the current g_pUiResourceContext widget.
void __cdecl SetUiResourceStateFlags(bool inputGateFlag, bool childHitTestFlag);

void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, const char* szText, short nMode,
                                        short nFlag, short nPointSize, TUiStyleRef styleRef,
                                        short nThemeCode);

// Set the current context edit control's max-character-count word (+0x9c).
void __cdecl SetUiResourceContextMaxCharCount(short maxChars);

void __cdecl SetUiResourceContextPictureId(int nPictureId);

// Store a FourCC group/mode code as the current context cluster's selected child tag.
void __cdecl SetUiResourceContextStringCode(int nCode);

void __cdecl ReplaceUiResourceContextPairBuffer(int styleWord, int packedColor);

void __cdecl SetUiResourceContextFlagsAndMetrics(short nField9C, short nStyleType, bool f70,
                                                 bool f6f, bool f6e, bool f6d, bool f6c, bool f71);

void __cdecl ApplyUiResourceColorTripletFromContext(bool nFlag0C, bool nTripletFlag, int colorA,
                                                    int colorB);

void __cdecl SetUiResourceContextNumberValueAndRange(int value, int minValue, int maxValue);

// IFuzzySet the g_pUiResourceContext cursor.
void __cdecl ClearUiResourceContext();

void __cdecl PopUiResourcePoolNode(unsigned int nameTag);

// Zeroes a contiguous dword resource-entry range; returns zero.
int __stdcall ClearUiResourceEntryDwords(int* destination, int count);
