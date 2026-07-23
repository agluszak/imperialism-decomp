#include "game/TAmtBar.h"
#include "game/TWindow.h"
// UI wrapper class quads extracted from trade_screen.

#include "game/THQButton.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include <new>
// SYNTHETIC: IMPERIALISM 0x0058b5c0
// THQButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058b640
// THQButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(THQButton, TPicture)

// FUNCTION: IMPERIALISM 0x0058b660
THQButton::THQButton() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0058b690
// THQButton::`scalar deleting destructor'
THQButton::~THQButton() {}
// FUNCTION: IMPERIALISM 0x0058b6e0
void THQButton::DoPostCreate(int arg) {
  short glyph = glyphBase84;
  TView::DoPostCreate(arg);
  glyph98 = 0;
  glyph90 = glyph;
  eventNumber60 = 0xc;
  timingWord92 = (short)(glyph + 1);
  glyph94 = (short)(glyph + 2);
  glyph96 = (short)(glyph + 3);
}

// FUNCTION: IMPERIALISM 0x0058b750
void THQButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  char mode = enabledState ? 1 : 0;
  if (mode != static_cast<char>(controlState64)) {
    controlState64 = static_cast<unsigned char>(mode);
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
      TWindow* owner = GetWindow();
      if (owner != 0) {
        owner->ForceRedraw();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058b7f0
void THQButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  if (commandId == 0xc) {
    if (controlState64 == 0) {
      control->InvokeSlot1CC(1, 1);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != 0x1f) {
    if (commandId != 0x20) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
    control->InvokeSlot1CC(0, 1);
    return;
  }
  control->InvokeSlot1CC(1, 1);
}

// FUNCTION: IMPERIALISM 0x0058b890
bool THQButton::IsSelected(short value, bool refreshNow) {
  if (IsEnabled()) {
    HiliteState(value != 0, refreshNow);
  }
  return controlState64 != 0;
}

// FUNCTION: IMPERIALISM 0x0058b8d0
void THQButton::SetSelectionStateAndRefreshBitmap(short selectionState) {
  glyph98 = selectionState;
  controlState64 = 0;
  short bitmapId;
  if (selectionState == 0) {
    bitmapId = glyph90;
  } else if (selectionState == 1) {
    bitmapId = glyph94;
  } else {
    bitmapId = glyph96;
  }
  SetPictureResourceIdAndRefresh(bitmapId, true);
  SetState(selectionState != 2 ? 1 : 0, false);
}
