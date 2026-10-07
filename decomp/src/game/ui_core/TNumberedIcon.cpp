#include "game/ui_core/TNumberedIcon.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_widgets/TMyNumberText.h"

IMPLEMENT_DYNCREATE(TNumberedIcon, TMegaPicture)

// FUNCTION: IMPERIALISM 0x005073a0
TNumberedIcon::TNumberedIcon() : TMegaPicture(), numberText(0) {}

// FUNCTION: IMPERIALISM 0x00507400
TNumberedIcon::~TNumberedIcon() {}

// FUNCTION: IMPERIALISM 0x00507420
void TNumberedIcon::INumberedIcon(TView* panel, int* offsetLayout, int* sizeLayout,
                                  int layoutParam4, int layoutParam5, short pictureId,
                                  short value) {
  IMegaPicture(panel, offsetLayout, sizeLayout, layoutParam4, layoutParam5, pictureId, 5);
  InstallNumberText();
  SetValue(value, true);

  if (numberText != 0) {
    // A 16x16 box hung off the icon's bottom-right corner.
    CRect numberBounds;
    numberBounds.right = frameWidth;
    numberBounds.bottom = frameHeight;
    numberBounds.left = numberBounds.right - 0x10;
    numberBounds.top = numberBounds.bottom - 0x10;
    numberText->ApplyBounds(&numberBounds, true);
  }
}

// FUNCTION: IMPERIALISM 0x005074e0
void TNumberedIcon::DoPostCreate(int arg) {
  TMegaPicture::DoPostCreate(arg);
  SetMode(5, true);
  InstallNumberText();
  if (numberText != 0) {
    int iconWidth = frameWidth;
    int iconHeight = frameHeight;
    CRect numberBounds(iconWidth - 0x10, iconHeight - 0x10, iconWidth, iconHeight);
    numberText->ApplyBounds(&numberBounds, true);
  }
}

// FUNCTION: IMPERIALISM 0x00507570
void TNumberedIcon::InstallNumberText() {
  if (this->numberText != 0) {
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
  this->numberText = numberText;
}

// FUNCTION: IMPERIALISM 0x005076d0
void TNumberedIcon::SetValue(short value, bool refresh) {
  if (numberText != 0) {
    numberText->SetControlValue(value, refresh);
  }
}
