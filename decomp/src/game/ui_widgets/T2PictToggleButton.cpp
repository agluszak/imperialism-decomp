#include "game/ui_widgets/T2PictToggleButton.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(T2PictToggleButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00584930
T2PictToggleButton::T2PictToggleButton() : TToggleButton() {}

// FUNCTION: IMPERIALISM 0x00584990
T2PictToggleButton::~T2PictToggleButton() {}

// FUNCTION: IMPERIALISM 0x005849b0
bool T2PictToggleButton::IsSelected() {
  if (this->glyphBase >= this->controlValue) {
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005849d0
void T2PictToggleButton::Select(bool isPressed, bool notifyParent) {
  (void)notifyParent;
  short sVar1 = glyphBase;
  int oldField3c = controlValue;

  if ((!isPressed && oldField3c < (int)sVar1) || (isPressed && (int)sVar1 < oldField3c)) {
    SetPictureRsrcID(static_cast<short>(oldField3c), false);
    controlValue = (int)sVar1;
  }
  PrepareForDrawing();
  PaintOrInvalidateControl(0);
}
