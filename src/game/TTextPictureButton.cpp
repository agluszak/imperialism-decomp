#include "game/TTextPictureButton.h"
// SYNTHETIC: IMPERIALISM 0x005724e0
// TTextPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005725b0
// TTextPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTextPictureButton, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x005725d0
TTextPictureButton::TTextPictureButton()
    : TUpDownPictureButton(), pointSize98(0), themeCode9A(0), themeCode9C(0) {}

// SYNTHETIC: IMPERIALISM 0x00572670
// TTextPictureButton::`scalar deleting destructor'
TTextPictureButton::~TTextPictureButton() {}

// FUNCTION: IMPERIALISM 0x00572710
void TTextPictureButton::InitializeTextPictureButtonAndTextStyle(TView* panel, int* offsetLayout,
                                                                 int* sizeLayout, short pictureId,
                                                                 CString* text, short pointSize,
                                                                 short themeCodeA,
                                                                 short themeCodeC) {
  InitializePictureEntryBaseAndRefresh(panel, offsetLayout, sizeLayout, 5, 5, pictureId);
  buttonText = *text;
  pointSize98 = pointSize;
  themeCode9A = themeCodeA;
  themeCode9C = themeCodeC;
}

// FUNCTION: IMPERIALISM 0x00572790
void TTextPictureButton::ApplyRectSlot110(RECT* rectBuffer) {}
