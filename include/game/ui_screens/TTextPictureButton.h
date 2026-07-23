#pragma once

#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006603a8
class TTextPictureButton : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TTextPictureButton)
  virtual ~TTextPictureButton() override;       // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x572790
  CString buttonText;                           // 0x94
  short pointSize98;                            // 0x98
  short themeCode9A;                            // 0x9A
  short themeCode9C;                            // 0x9C

  // Second-phase init: runs the TPicture base init (5, 5 layout filler), copies the
  // button label, and stores the text point size / theme codes consumed by
  // Draw. 0x572710, __thiscall, RET 0x20.
  void InitializeTextPictureButtonAndTextStyle(TView* panel, int* offsetLayout, int* sizeLayout,
                                               short pictureId, CString* text, short pointSize,
                                               short themeCodeA, short themeCodeC);

  TTextPictureButton();
};

ASSERT_SIZE(TTextPictureButton, 0xa0);
