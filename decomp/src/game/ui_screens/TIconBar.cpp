#include "game/ui_screens/TIconBar.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TIconBar, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00505ff0
TIconBar::TIconBar() {}

// FUNCTION: IMPERIALISM 0x00506050
TIconBar::~TIconBar() {}

// FUNCTION: IMPERIALISM 0x00506070
void TIconBar::IIconBar(TView* panel, int* position, int* size, int layoutParam4, int layoutParam5,
                        short pictureId, int numIcons) {
  IPicture(panel, position, size, layoutParam4, layoutParam5, pictureId);
  SetNumIcons(static_cast<short>(numIcons));
}

// FUNCTION: IMPERIALISM 0x005060c0
void TIconBar::SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow) {
  iconAtlasFrame = nPictureId - 700;
  TPicture::SetPictureRsrcID(nPictureId, fRefreshNow);
}

// FUNCTION: IMPERIALISM 0x005060f0
void TIconBar::SetNumIcons(short numIcons) {
  this->numIcons = numIcons;
}

// FUNCTION: IMPERIALISM 0x00506110
void TIconBar::SetNumIcons(short numIcons, unsigned char refreshNow) {
  SetNumIcons(numIcons);
  if (refreshNow != 0) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x00506150
void TIconBar::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CRect contentRect;
  BuildInsetContentRect(&contentRect);

  short slotWidth = static_cast<short>(contentRect.right - contentRect.left) / (numIcons + 1);
  if (slotWidth > 0x20) {
    slotWidth = 0x20;
  }
  iconSpacing = slotWidth;

  RECT srcRect = {iconAtlasFrame * 0x20, 0, iconAtlasFrame * 0x20 + 0x20, 0x18};
  RECT dstRect = {contentRect.left, contentRect.top, contentRect.left + 0x20,
                  contentRect.top + 0x18};

  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);
  for (short i = 0; i < numIcons; ++i) {
    BlitRectWithOptionalTransparency(g_pMacViewMgr->commodityIconWorld->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    dstRect.left += slotWidth;
    dstRect.right += slotWidth;
  }
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
