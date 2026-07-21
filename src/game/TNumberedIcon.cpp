#include "game/TNumberedIcon.h"
#include "game/TMyNumberText.h"
// SYNTHETIC: IMPERIALISM 0x005072e0
// TNumberedIcon::CreateObject

// SYNTHETIC: IMPERIALISM 0x00507380
// TNumberedIcon::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNumberedIcon, TMegaPicture)

// FUNCTION: IMPERIALISM 0x005073a0
TNumberedIcon::TNumberedIcon() : TMegaPicture(), numberTextAc(0) {}

// SYNTHETIC: IMPERIALISM 0x005073d0
// TNumberedIcon::`scalar deleting destructor'
TNumberedIcon::~TNumberedIcon() {}

// FUNCTION: IMPERIALISM 0x005074e0
void TNumberedIcon::DoPostCreate(int arg) {
  TMegaPicture::DoPostCreate(arg);
  AssignFlags98AndMaybeRefresh(5, 1);
  InstallNumberText();
  // The original then, when fieldAc is set, builds a RECT from frameWidth34/frameHeight38
  // (each offset by -0x10 for two of the four fields; the remaining two aren't resolved)
  // and calls fieldAc->ApplyBounds(&rect, 1) -- left unmodeled pending the full rect shape.
}

// FUNCTION: IMPERIALISM 0x00507570
void TNumberedIcon::InstallNumberText() {
  if (numberTextAc != 0) {
    return;
  }

  TMyNumberText* numberText = new TMyNumberText;
  int offsetLayout[2] = {0, 0};
  int sizeLayout[2] = {1, 1};
  numberText->ConstructTNumberTextBaseState(this, offsetLayout, sizeLayout, 0, 0, 9999);

  TUiTextStyleDescriptor style;
  style.textColor = 0;
  style.fontFamily = 3;
  style.fontStyleFlags = 0;
  style.fontSize = 9;
  numberText->SetTextStyleAndMaybeRefresh(&style, 0);
  numberText->SetEnabled(1, 0);
  numberTextAc = numberText;
}

// FUNCTION: IMPERIALISM 0x005076d0
void TNumberedIcon::SetValue(short value, unsigned char refresh) {
  if (numberTextAc != 0) {
    numberTextAc->SetControlValue(value, refresh);
  }
}
