#include "game/ui_core/TNumberedIcon.h"
#include "game/ui_widgets/TMyNumberText.h"
// SYNTHETIC: IMPERIALISM 0x005072e0
// TNumberedIcon::CreateObject

// SYNTHETIC: IMPERIALISM 0x00507380
// TNumberedIcon::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNumberedIcon, TMegaPicture)

// FUNCTION: IMPERIALISM 0x005073a0
TNumberedIcon::TNumberedIcon() : TMegaPicture(), numberTextAc(0) {}

// SYNTHETIC: IMPERIALISM 0x005073d0
// TNumberedIcon::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00507400
TNumberedIcon::~TNumberedIcon() {}

// FUNCTION: IMPERIALISM 0x005074e0
void TNumberedIcon::DoPostCreate(int arg) {
  TMegaPicture::DoPostCreate(arg);
  AssignFlags98AndMaybeRefresh(5, 1);
  InstallNumberText();
  if (numberTextAc != 0) {
    CRect numberBounds(frameWidth34 - 0x10, frameHeight38 - 0x10, frameWidth34, frameHeight38);
    numberTextAc->ApplyBounds(&numberBounds, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00507570
void TNumberedIcon::InstallNumberText() {
  if (numberTextAc != 0) {
    return;
  }

  TMyNumberText* numberText = new TMyNumberText;
  int offsetLayout[2] = {0, 0};
  int sizeLayout[2] = {1, 1};
  numberText->InitializeNumberText(this, offsetLayout, sizeLayout, 0, 0, 9999);

  TextStyle style;
  style.textColor = 0;
  style.fontFamily = 3;
  style.fontStyleFlags = 0;
  style.fontSize = 9;
  numberText->InstallTextStyle(style, 0);
  numberText->SetEnabled(1, 0);
  numberTextAc = numberText;
}

// FUNCTION: IMPERIALISM 0x005076d0
void TNumberedIcon::SetValue(short value, unsigned char refresh) {
  if (numberTextAc != 0) {
    numberTextAc->SetControlValue(value, refresh);
  }
}
