#include "game/ui_screens/TColorKeyPicture.h"
#include "game/ui_tags_common.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
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
      static_cast<TPicture*>(GetWindow()->ResolveControlByTag(kControlTagMain)); // 'main'
  if (background == 0) {
    background =
        static_cast<TPicture*>(GetWindow()->ResolveControlByTag(kControlTagBack)); // 'back'
  }
  if (background == 0) {
    background =
        static_cast<TPicture*>(GetWindow()->ResolveControlByTag(kControlTagDialog)); // 'GOLD'
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
void TColorKeyPicture::SetPictureResourceIdAndRefresh(short nPictureId, unsigned char fRefreshNow) {
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
