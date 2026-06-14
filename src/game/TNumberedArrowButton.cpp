// UI wrapper class quads extracted from trade_screen.

#include "game/TNumberedArrowButton.h"
CRuntimeClass g_pClassDescTNumberedArrowButton = {0};
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058c1e0
TNumberedArrowButton* __cdecl CreateTNumberedArrowButtonInstance(void) {
  return new TNumberedArrowButton();
}

// FUNCTION: IMPERIALISM 0x0058c280
CRuntimeClass* TNumberedArrowButton::GetRuntimeClass() {
  return &g_pClassDescTNumberedArrowButton;
}

// FUNCTION: IMPERIALISM 0x0058c2a0
TNumberedArrowButton::TNumberedArrowButton() : TControl(), value84(0), value86(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058c2e0
// TNumberedArrowButton::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

#include "game/TAmtBar.h"
#include "game/CRuntimeClass.h"

// FUNCTION: IMPERIALISM 0x0058b750
void TNumberedArrowButton::OrphanCallChain_C3_I43_0058b750(char mode, char refreshParent) {
  if (mode != *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x64)) {
    *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x64) = mode;
    short bitmapId = 0;
    short modeState = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x98);
    if (mode == 0) {
      if (modeState == 0) {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x90);
      } else if (modeState == 1) {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x94);
      } else {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x96);
      }
    } else {
      bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x92);
    }
    reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
    if (refreshParent != 0) {
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(this)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058b8d0
void TNumberedArrowButton::OrphanCallChain_C2_I37_0058b8d0(short mode) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x98) = mode;
  *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x64) = 0;
  short bitmapId = 0;
  if (mode == 0) {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x90);
  } else if (mode == 1) {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x94);
  } else {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x96);
  }
  reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
  reinterpret_cast<TAmtBar*>(this)->SetState(mode != 2, 0);
}

// FUNCTION: IMPERIALISM 0x0058c330
void TNumberedArrowButton::OrphanCallChain_C1_I08_0058c330(short value84Arg, char refreshFlag) {
  value84 = value84Arg;
  if (refreshFlag != '\0') {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0058c360
void TNumberedArrowButton::OrphanCallChain_C2_I23_0058c360(short value86Arg, char refreshFlag) {
  RECT bounds;
  if (value86 != value86Arg) {
    if (refreshFlag != '\0') {
      RefreshControl();
      QueryBounds(&bounds);
    }
    value86 = value86Arg;
  }
}
