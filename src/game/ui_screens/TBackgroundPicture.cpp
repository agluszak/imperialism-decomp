#include "game/ui_screens/TBackgroundPicture.h"

#include "game/ui_core/TPicture.h"
// SYNTHETIC: IMPERIALISM 0x00572bd0
// TBackgroundPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00572c60
// TBackgroundPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBackgroundPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00572c80
TBackgroundPicture::TBackgroundPicture() {}

// SYNTHETIC: IMPERIALISM 0x00572cb0
// TBackgroundPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00572ce0
TBackgroundPicture::~TBackgroundPicture() {}

// FUNCTION: IMPERIALISM 0x00572d00
void TBackgroundPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
}
