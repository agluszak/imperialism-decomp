#pragma once

#include "game/app/ui_resource_builder.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x00426fa0
UI_RESOURCE_BUILDER_INLINE void __cdecl
SetUiResourceContextFlagsAndMetrics(short nField9C, short nStyleType, bool f70, bool f6f, bool f6e,
                                    bool f6d, bool f6c, bool f71) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->topmostFlag70 = f70;
  window->resourceFlag6f = f6f;
  window->resourceFlag6e = f6e;
  window->useCaptionedFrameFlag6d = f6d;
  window->resourceFlag6c = f6c;
  window->resourceFlag71 = f71;
  window->windowFlags = static_cast<unsigned short>(nField9C);
  window->windowStyleType = nStyleType;
}

// FUNCTION: IMPERIALISM 0x00427010
UI_RESOURCE_BUILDER_INLINE void __cdecl
ApplyUiResourceColorTripletFromContext(unsigned char nFlag0C, unsigned char nTripletFlag,
                                       int colorA, int colorB) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->GetDialogBehavior()->SetEnabled(nFlag0C);
  window->GetDialogBehavior()->SetUiColorDescriptorGoldTriplet(nTripletFlag, colorA, colorB);
}

// FUNCTION: IMPERIALISM 0x00427060
UI_RESOURCE_BUILDER_INLINE void __cdecl ReplaceUiResourceContextPairBuffer(int styleWord,
                                                                           int packedColor) {
  TView* context = g_pUiResourceContext;
  delete context->stylePayload48;
  context->stylePayload48 = new TUiStyleBytes();
  context->stylePayload48->styleWord = styleWord;
  context->stylePayload48->packedColor = packedColor;
}

#ifndef UI_RESOURCE_BUILDER_OMIT_STYLE_REF_CTOR
// FUNCTION: IMPERIALISM 0x004270e0
UI_RESOURCE_BUILDER_INLINE TUiStyleRef::TUiStyleRef(int value) {
  this->value = value;
}
#endif
