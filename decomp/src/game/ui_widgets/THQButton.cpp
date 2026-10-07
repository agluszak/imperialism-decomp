#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/THQButton.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include <new>

IMPLEMENT_DYNCREATE(THQButton, TPicture)

// FUNCTION: IMPERIALISM 0x0058b660
THQButton::THQButton() : TPicture() {}

// FUNCTION: IMPERIALISM 0x0058b6c0
THQButton::~THQButton() {}

// FUNCTION: IMPERIALISM 0x0058b6e0
void THQButton::DoPostCreate(int arg) {
  short glyph = glyphBase;
  TView::DoPostCreate(arg);
  selectionState = 0;
  normalBitmapId = glyph;
  eventNumber = 0xc;
  highlightedBitmapId = static_cast<short>(glyph + 1);
  selectedBitmapId = static_cast<short>(glyph + 2);
  unavailableBitmapId = static_cast<short>(glyph + 3);
}

// FUNCTION: IMPERIALISM 0x0058b750
void THQButton::HiliteState(unsigned char enabledState, bool refreshNow) {
  if (enabledState != controlState) {
    controlState = enabledState;
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
    SetPictureRsrcID(bitmapId, 1);
    if (refreshNow) {
      GetWindow()->ForceRedraw();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058b7f0
void THQButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (controlState == 0) {
      SetState(true, true);
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != kControlCommandHiliteOn) {
    if (commandId != kControlCommandHiliteOff) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
    SetState(false, true);
    return;
  }
  SetState(true, true);
}

// FUNCTION: IMPERIALISM 0x0058b890
void THQButton::SetState(bool value, bool refreshNow) {
  if (IsEnabled()) {
    HiliteState(value, refreshNow);
  }
}

// FUNCTION: IMPERIALISM 0x0058b8d0
void THQButton::SetMode(short selectionState) {
  bool enabledState = selectionState != 2;
  this->selectionState = selectionState;
  controlState = 0;
  if (selectionState == 0) {
    SetPictureRsrcID(normalBitmapId, true);
  } else if (selectionState == 1) {
    SetPictureRsrcID(selectedBitmapId, true);
  } else {
    SetPictureRsrcID(unavailableBitmapId, true);
  }
  ViewEnable(enabledState, false);
}
