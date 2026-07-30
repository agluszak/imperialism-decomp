#include "game/ui_core/TNumberedIcon.h"
#include "game/ui_core/TNumberText.h"
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

// FUNCTION: IMPERIALISM 0x00507420
void TNumberedIcon::INumberedIcon(TView* panel, int* offsetLayout, int* sizeLayout,
                                  int layoutParam4, int layoutParam5, short pictureId,
                                  short value) {
  IMegaPicture(panel, offsetLayout, sizeLayout, layoutParam4, layoutParam5, pictureId, 5);
  InstallNumberText();
  SetValue(value, 1);

  if (numberTextAc != 0) {
    // A 16x16 box hung off the icon's bottom-right corner.
    CRect numberBounds;
    numberBounds.right = frameWidth34;
    numberBounds.bottom = frameHeight38;
    numberBounds.left = numberBounds.right - 0x10;
    numberBounds.top = numberBounds.bottom - 0x10;
    numberTextAc->ApplyBounds(&numberBounds, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005074e0
void TNumberedIcon::DoPostCreate(int arg) {
  TMegaPicture::DoPostCreate(arg);
  AssignFlags98AndMaybeRefresh(5, 1);
  InstallNumberText();
  if (numberTextAc != 0) {
    // 0x00507511 loads +0x34 before +0x38. MSVC evaluates constructor arguments
    // right-to-left, so passing the fields directly would load frameHeight38 first;
    // sequencing them into locals pins the original order.
    int iconWidth = frameWidth34;
    int iconHeight = frameHeight38;
    CRect numberBounds(iconWidth - 0x10, iconHeight - 0x10, iconWidth, iconHeight);
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
  numberText->INumberText(this, offsetLayout, sizeLayout, 0, 0, 9999);

  TextStyle style;
  style.textColor = 0;
  style.fontFamily = 3;
  style.fontStyleFlags = 0;
  style.fontSize = 9;
  numberText->InstallTextStyle(style, 0);
  numberText->Show(1, 0);
  numberTextAc = numberText;
}

// FUNCTION: IMPERIALISM 0x005076d0
void TNumberedIcon::SetValue(short value, unsigned char refresh) {
  if (numberTextAc != 0) {
    numberTextAc->SetControlValue(value, refresh);
  }
}
