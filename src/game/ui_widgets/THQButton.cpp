#include "game/ui_core/TWindow.h"
// UI wrapper class quads extracted from trade_screen.

#include "game/ui_widgets/THQButton.h"
#include "game/ui_core/TViewMgr.h"
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
// FUNCTION: IMPERIALISM 0x0058b6c0
THQButton::~THQButton() {}
// FUNCTION: IMPERIALISM 0x0058b6e0
void THQButton::DoPostCreate(int arg) {
  short glyph = glyphBase84;
  TView::DoPostCreate(arg);
  selectionState = 0;
  normalBitmapId = glyph;
  eventNumber60 = 0xc;
  highlightedBitmapId = static_cast<short>(glyph + 1);
  selectedBitmapId = static_cast<short>(glyph + 2);
  unavailableBitmapId = static_cast<short>(glyph + 3);
}

// FUNCTION: IMPERIALISM 0x0058b750
void THQButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  if (enabledState != controlState64) {
    controlState64 = enabledState;
    short bitmapId = 0;
    if (enabledState == 0) {
      short modeState = selectionState;
      if (modeState == 0) {
        bitmapId = normalBitmapId;
      } else if (modeState == 1) {
        bitmapId = selectedBitmapId;
      } else {
        bitmapId = unavailableBitmapId;
      }
    } else {
      bitmapId = highlightedBitmapId;
    }
    SetPictureResourceIdAndRefresh(bitmapId, 1);
    if (refreshNow) {
      GetWindow()->ForceRedraw();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058b7f0
void THQButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (controlState64 == 0) {
      IsSelected(1, 1);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != kControlCommandHiliteOn) {
    if (commandId != kControlCommandHiliteOff) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
    IsSelected(0, 1);
    return;
  }
  IsSelected(1, 1);
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
  this->selectionState = selectionState;
  controlState64 = 0;
  short bitmapId;
  if (selectionState == 0) {
    bitmapId = normalBitmapId;
  } else if (selectionState == 1) {
    bitmapId = selectedBitmapId;
  } else {
    bitmapId = unavailableBitmapId;
  }
  SetPictureResourceIdAndRefresh(bitmapId, true);
  SetState(selectionState != 2 ? 1 : 0, false);
}
