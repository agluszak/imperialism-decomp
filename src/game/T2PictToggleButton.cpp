#include "game/T2PictToggleButton.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00584890
T2PictToggleButton* __cdecl CreateT2PictToggleButtonInstance(void) {
  return new T2PictToggleButton();
}
// SYNTHETIC: IMPERIALISM 0x00584910
// T2PictToggleButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(T2PictToggleButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00584930
T2PictToggleButton::T2PictToggleButton() : TToggleButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00584960
// T2PictToggleButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005849b0
bool T2PictToggleButton::IsSelected() {
  return this->field3c <= this->glyphBase84;
}

// FUNCTION: IMPERIALISM 0x005849d0
void T2PictToggleButton::Select(bool isPressed, bool notifyParent) {
  (void)notifyParent;
  void** ppuVar2;

  short sVar1 = glyphBase84;
  int oldField3c = field3c;

  if (((isPressed == false) && (oldField3c < (int)sVar1)) ||
      ((isPressed == true && ((int)sVar1 < oldField3c)))) {
    reinterpret_cast<void(__cdecl*)(short, int)>(reinterpret_cast<void***>(this)[0][0x72])(
        (short)oldField3c, 0);
    field3c = (int)sVar1;
  }
  ppuVar2 = reinterpret_cast<void***>(this)[0];
  reinterpret_cast<void(__cdecl*)()>(ppuVar2[0x3e])();
  reinterpret_cast<void(__cdecl*)(int)>(ppuVar2[0x45])(0);
}

T2PictToggleButton::~T2PictToggleButton() {}
