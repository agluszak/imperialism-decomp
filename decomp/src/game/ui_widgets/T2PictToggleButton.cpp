#include "game/ui_widgets/T2PictToggleButton.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00584890
// T2PictToggleButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x00584910
// T2PictToggleButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(T2PictToggleButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00584930
T2PictToggleButton::T2PictToggleButton() : TToggleButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00584960
// T2PictToggleButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00584990
T2PictToggleButton::~T2PictToggleButton() {}

// FUNCTION: IMPERIALISM 0x005849b0
bool T2PictToggleButton::IsSelected() {
  if (this->glyphBase84 >= this->controlValue3c) {
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005849d0
void T2PictToggleButton::Select(bool isPressed, bool notifyParent) {
  (void)notifyParent;
  short sVar1 = glyphBase84;
  int oldField3c = controlValue3c;

  if (((isPressed == false) && (oldField3c < (int)sVar1)) ||
      ((isPressed == true && ((int)sVar1 < oldField3c)))) {
    SetPictureResourceIdAndRefresh(static_cast<short>(oldField3c), false);
    controlValue3c = (int)sVar1;
  }
  PrepareForDrawing();
  PaintOrInvalidateControl(0);
}
