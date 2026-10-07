#pragma once

#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006603a8
class TTextPictureButton : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TTextPictureButton)
  virtual ~TTextPictureButton() override;
  virtual void Draw(RECT* rectBuffer) override;
  CString buttonText;
  short pointSize;
  short textThemeCode;
  short shadowThemeCode;

  void ITextPictureButton(TView* panel, int* offsetLayout, int* sizeLayout, short pictureId,
                          CString* text, short pointSize, short themeCodeA, short themeCodeC);

  TTextPictureButton();
};

ASSERT_SIZE(TTextPictureButton, 0xa0);
