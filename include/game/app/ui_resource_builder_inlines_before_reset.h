#pragma once

#include "game/app/ui_resource_builder.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TView.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x0041b210
inline void __cdecl RegisterUiResourceEntry(unsigned int nameTag, unsigned int controlTag,
                                            TView* widget, int offsetX, int offsetY, int width,
                                            int height, int stateValue, int enabledState,
                                            unsigned int ownerTag, int field3cValue) {
  (void)nameTag;
  (void)ownerTag;

  TView* parent;
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    const CList<TView*, TView*>& buildStack = g_UiWidgetBuildStack006a13e0;
    parent = buildStack.GetTail();
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(widget);

  int offsetLayout[2];
  int sizeLayout[2];
  offsetLayout[0] = offsetX;
  offsetLayout[1] = offsetY;
  sizeLayout[0] = width;
  sizeLayout[1] = height;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offsetLayout, sizeLayout, 0, 0, 1);
  widget->controlTag = static_cast<int>(controlTag);
  widget->controlValue3c = field3cValue;
  widget->Show(enabledState, 0);
  widget->ViewEnable(stateValue, 0);
}

// FUNCTION: IMPERIALISM 0x0041b3a0
inline void __cdecl SetUiResourceStateFlags(bool inputGateFlag4c, bool childHitTestFlag4d) {
  TView* context = g_pUiResourceContext;
  context->inputGateFlag4c = inputGateFlag4c;
  context->childHitTestFlag4d = childHitTestFlag4d;
}

// FUNCTION: IMPERIALISM 0x0041b3d0
inline void __cdecl SetUiResourceContextPictureId(int nPictureId) {
  static_cast<TPicture*>(g_pUiResourceContext)
      ->SetPictureResourceIdAndRefresh(static_cast<short>(nPictureId), 0);
}

// FUNCTION: IMPERIALISM 0x0041b400
inline void __cdecl SetUiResourceContextStringCode(int nCode) {
  static_cast<TCluster*>(g_pUiResourceContext)->selectedChildTag = nCode;
}
