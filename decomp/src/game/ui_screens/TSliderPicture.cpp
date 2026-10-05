#include "game/ui_screens/TSliderPicture.h"

#include "game/ui_core/TPicture.h"

IMPLEMENT_DYNCREATE(TSliderPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00573a20
TSliderPicture::TSliderPicture() {}

// FUNCTION: IMPERIALISM 0x00573a80
TSliderPicture::~TSliderPicture() {}

// FUNCTION: IMPERIALISM 0x00573aa0
void TSliderPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
}
