#include "game/TColorKeyPicture.h"

#include "game/TDisplayMgr.h"
#include "game/global_data_tables.h"
// SYNTHETIC: IMPERIALISM 0x00572d20
// TColorKeyPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00572dc0
// TColorKeyPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TColorKeyPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00572de0
TColorKeyPicture::TColorKeyPicture() : TNoHilitePicture(), colorKeySurface94(0) {}

// SYNTHETIC: IMPERIALISM 0x00572e10
// TColorKeyPicture::`scalar deleting destructor'
TColorKeyPicture::~TColorKeyPicture() {}

// FUNCTION: IMPERIALISM 0x00572e60
void TColorKeyPicture::Draw(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00573040
void TColorKeyPicture::SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) {}

// FUNCTION: IMPERIALISM 0x00573090
void TColorKeyPicture::Free() {
  if (colorKeySurface94 != 0) {
    g_pDisplayMgr->RemoveGWorld(colorKeySurface94);
  }
  colorKeySurface94 = 0;
  TView::Free();
}
