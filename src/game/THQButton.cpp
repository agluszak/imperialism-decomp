#include "game/TAmtBar.h"
// UI wrapper class quads extracted from trade_screen.

#include "game/THQButton.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/CRuntimeClass.h"

CRuntimeClass g_pClassDescTHQButton = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x0058b5c0
void* __cdecl CreateTHQButtonInstance(void) {
  return new THQButton();
}

// FUNCTION: IMPERIALISM 0x0058b640
CRuntimeClass* THQButton::GetRuntimeClass() const {
  return &g_pClassDescTHQButton;
}

// FUNCTION: IMPERIALISM 0x0058b660
THQButton::THQButton() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058b690
// THQButton::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058b6e0
void THQButton::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  short glyph = glyphBase84;
  thunk_NoOpUiLifecycleHook();
  glyph98 = 0;
  glyph90 = glyph;
  hasCommandTagResource = 0xc;
  timingWord92 = (short)(glyph + 1);
  glyph94 = (short)(glyph + 2);
  glyph96 = (short)(glyph + 3);
}

// FUNCTION: IMPERIALISM 0x0058b750
void THQButton::SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) {
  char mode = enabledState ? 1 : 0;
  if (mode != static_cast<char>(commandTagResourceByte)) {
    commandTagResourceByte = static_cast<unsigned char>(mode);
    short bitmapId = 0;
    short modeState = glyph98;
    if (mode == 0) {
      if (modeState == 0) {
        bitmapId = glyph90;
      } else if (modeState == 1) {
        bitmapId = glyph94;
      } else {
        bitmapId = glyph96;
      }
    } else {
      bitmapId = timingWord92;
    }
    reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
    if (refreshNow) {
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058b7f0
void THQButton::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  if (commandId == 0xc) {
    if (commandTagResourceByte == 0) {
      control->InvokeSlot1CC(1, 1);
    }
    TControl::HandleEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != 0x1f) {
    if (commandId != 0x20) {
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
    }
    control->InvokeSlot1CC(0, 1);
    return;
  }
  control->InvokeSlot1CC(1, 1);
}

// FUNCTION: IMPERIALISM 0x0058b890
bool THQButton::IsSelected(short value, bool refreshNow) {
  if (GetBoolSlot28()) {
    SetControlStateFlagAndMaybeRefresh(value != 0, refreshNow);
  }
  return commandTagResourceByte != 0;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

THQButton::~THQButton() {}
