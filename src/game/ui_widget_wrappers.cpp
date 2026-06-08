#include "game/TAmtBar.h"

#include "game/TNumberedArrowButton.h"
#include "game/TPlacard.h"
#include "game/TCivilianButton.h"
#include "game/THQButton.h"
#include "game/TCombatReportView.h"
#include "game/TPictureResourceEntryBase.h"

// UI wrapper class quads extracted from trade_screen.


#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058c330
void __fastcall OrphanCallChain_C1_I08_0058c330(TNumberedArrowButton* button, int unusedEdx,
                                                short value84, char refreshFlag) {
  (void)unusedEdx;
  button->value84 = value84;
  if (refreshFlag != '\0') {
    reinterpret_cast<TAmtBar*>(button)->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0058c360
void __fastcall OrphanCallChain_C2_I23_0058c360(TNumberedArrowButton* button, int unusedEdx,
                                                short value86, char refreshFlag) {
  (void)unusedEdx;
  int bounds[4];
  if (button->value86 != value86) {
    if (refreshFlag != '\0') {
      reinterpret_cast<TAmtBar*>(button)->RefreshControl();
      reinterpret_cast<TAmtBar*>(button)->QueryBounds(bounds);
    }
    button->value86 = value86;
  }
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void __fastcall WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
    TNumberedArrowButton* button, int unusedEdx, int* cursorPoint, int hitArg) {
  (void)unusedEdx;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(button);
  if (control->IsActionable() != '\0') {
    if (cursorPoint[1] < button->field38 / 2) {
      button->field4e = 0x100;
      reinterpret_cast<void(__fastcall*)(TNumberedArrowButton*, int*, int)>(
          ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
      return;
    }
    button->field4e = (short)0xffff;
  }
  reinterpret_cast<void(__fastcall*)(TNumberedArrowButton*, int*, int)>(
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

void operator delete(void* p) {
  extern void FreeHeapBufferIfNotNull(unsigned int);
  FreeHeapBufferIfNotNull((unsigned int)p);
}

