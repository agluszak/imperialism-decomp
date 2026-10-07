#include "game/ui_widgets/T2PictToggleButton.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(T2PictToggleButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00584930
T2PictToggleButton::T2PictToggleButton() : TToggleButton() {}

// FUNCTION: IMPERIALISM 0x00584990
T2PictToggleButton::~T2PictToggleButton() {}

// FUNCTION: IMPERIALISM 0x005849b0
bool T2PictToggleButton::IsSelected() {
  return glyphBase >= controlValue;
}

// FUNCTION: IMPERIALISM 0x005849d0
void T2PictToggleButton::Select(bool isPressed, bool notifyParent) {
  short glyphThreshold = glyphBase;
  int oldField3c = controlValue;

  if ((!isPressed && oldField3c < static_cast<int>(glyphThreshold)) ||
      (isPressed && static_cast<int>(glyphThreshold) < oldField3c)) {
    SetPictureRsrcID(static_cast<short>(oldField3c), false);
    controlValue = static_cast<int>(glyphThreshold);
  }
  PrepareForDrawing();
  PaintOrInvalidateControl(0);
}
