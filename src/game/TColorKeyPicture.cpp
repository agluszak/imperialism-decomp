#include "game/TColorKeyPicture.h"

#include "game/TDisplayMgr.h"
#include "game/CDib.h"
#include "game/CDibPal.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TPicture.h"
#include "game/TWindow.h"
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
void TColorKeyPicture::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  delete g_pColorKeyCompositeDib;
  g_pColorKeyCompositeDib = new CDib(*cachedBitmap);

  TPicture* background =
      static_cast<TPicture*>(GetWindow()->ResolveControlByTag(0x6d61696e)); // 'main'
  if (background == 0) {
    background = static_cast<TPicture*>(GetWindow()->ResolveControlByTag(0x6261636b)); // 'back'
  }
  if (background == 0) {
    background = static_cast<TPicture*>(GetWindow()->ResolveControlByTag(0x444c4f47)); // 'GOLD'
  }

  CPoint position;
  GetAbsolutePosition(&position);
  background->cachedBitmap->BlitSurfaceRectSkippingTransparentColor(
      g_pColorKeyCompositeDib, position.x, position.y, frameWidth34, frameHeight38, 0, 0, -1);
  cachedBitmap->BlitSurfaceRectSkippingTransparentColor(g_pColorKeyCompositeDib, 0, 0, frameWidth34,
                                                        frameHeight38, 0, 0, 0x1000010);

  g_pModuleLibraryCacheState->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(
      GetActiveQuickDrawDc(), FALSE);
  int width = frameWidth34;
  int height = frameHeight38;
  g_pColorKeyCompositeDib->StretchDibitsFromStoredBitmapToHdcSimple(
      GetActiveQuickDrawDc(), position.x, position.y, width, height);

  delete g_pColorKeyCompositeDib;
  g_pColorKeyCompositeDib = 0;
}

// FUNCTION: IMPERIALISM 0x00573040
void TColorKeyPicture::SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) {
  if (colorKeySurface94 != 0) {
    g_pDisplayMgr->RemoveGWorld(colorKeySurface94);
  }
  colorKeySurface94 = 0;
  TPicture::SetPictureResourceIdAndRefresh(nPictureId, fRefreshNow);
}

// FUNCTION: IMPERIALISM 0x00573090
void TColorKeyPicture::Free() {
  if (colorKeySurface94 != 0) {
    g_pDisplayMgr->RemoveGWorld(colorKeySurface94);
  }
  colorKeySurface94 = 0;
  TView::Free();
}
