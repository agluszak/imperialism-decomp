// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058c330
void __fastcall OrphanCallChain_C1_I08_0058c330(NumberedArrowButtonState* button, int unusedEdx,
                                                short value84, char refreshFlag) {
  (void)unusedEdx;
  button->value84 = value84;
  if (refreshFlag != '\0') {
    reinterpret_cast<TradeControl*>(button)->InvokeSlotE4();
  }
}

// FUNCTION: IMPERIALISM 0x0058c360
void __fastcall OrphanCallChain_C2_I23_0058c360(NumberedArrowButtonState* button, int unusedEdx,
                                                short value86, char refreshFlag) {
  (void)unusedEdx;
  int bounds[4];
  if (button->value86 != value86) {
    if (refreshFlag != '\0') {
      reinterpret_cast<TradeControl*>(button)->InvokeSlotE4();
      reinterpret_cast<TradeControl*>(button)->QueryBounds(bounds);
    }
    button->value86 = value86;
  }
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void __fastcall WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
    NumberedArrowButtonState* button, int unusedEdx, int* cursorPoint, int hitArg) {
  (void)unusedEdx;
  TradeControl* control = reinterpret_cast<TradeControl*>(button);
  if (control->IsActionable() != '\0') {
    if (cursorPoint[1] < button->width38 / 2) {
      button->hoverTag4e = 0x100;
      reinterpret_cast<void(__fastcall*)(NumberedArrowButtonState*, int*, int)>(
          ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
      return;
    }
    button->hoverTag4e = (short)0xffff;
  }
  reinterpret_cast<void(__fastcall*)(NumberedArrowButtonState*, int*, int)>(
      ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
}

/* [TinyOrphan] tiny setter dword to [ECX+0x60]; pattern=MOV EAX,dword ptr [ESP + 0x4] | MOV dword
   ptr [ECX + 0x60],EAX | RET 0x4 */

struct DwordAtOffset60State {
  unsigned char pad_00_to_5f[0x60];
  int field60;
};

// FUNCTION: IMPERIALISM 0x0058e440
void __fastcall OrphanTiny_SetDwordEcxOffset_60_0058e440(DwordAtOffset60State* state, int unusedEdx,
                                                         int value) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  state->field60 = value;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
