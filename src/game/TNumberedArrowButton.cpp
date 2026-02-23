// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058C1E0
NumberedArrowButtonState* __cdecl CreateTNumberedArrowButtonInstance(void) {
  NumberedArrowButtonState* button =
      reinterpret_cast<NumberedArrowButtonState*>(AllocateWithFallbackHandler(0x88));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructUiCommandTagResourceEntryBase(button);
    button->vftable = reinterpret_cast<void*>(&g_vtblTNumberedArrowButton);
    button->value84 = 0;
    button->value86 = 0;
  }
  return button;
}

// FUNCTION: IMPERIALISM 0x0058C280
void* __cdecl GetTNumberedArrowButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTNumberedArrowButton);
}

// FUNCTION: IMPERIALISM 0x0058C2A0
NumberedArrowButtonState* __fastcall
ConstructTNumberedArrowButtonBaseState(NumberedArrowButtonState* button) {
  TradeScreenRuntimeBridge::ConstructUiCommandTagResourceEntryBase(button);
  button->vftable = reinterpret_cast<void*>(&g_vtblTNumberedArrowButton);
  button->value84 = 0;
  button->value86 = 0;
  return button;
}

// FUNCTION: IMPERIALISM 0x0058C2E0
NumberedArrowButtonState* __fastcall
DestructTNumberedArrowButtonAndMaybeFree(NumberedArrowButtonState* button, int unusedEdx,
                                         unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
