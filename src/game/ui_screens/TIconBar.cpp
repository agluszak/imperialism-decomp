#include "game/ui_screens/TIconBar.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x00505f50
// TIconBar::CreateObject

// SYNTHETIC: IMPERIALISM 0x00505fd0
// TIconBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIconBar, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00505ff0
TIconBar::TIconBar() : TNoHilitePicture() {}

// SYNTHETIC: IMPERIALISM 0x00506020
// TIconBar::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00506050
TIconBar::~TIconBar() {}

// FUNCTION: IMPERIALISM 0x00506070
void TIconBar::IIconBar(TView* panel, int* position, int* size, int layoutParam4, int layoutParam5,
                        short pictureId, int numIcons) {
  IPicture(panel, position, size, layoutParam4, layoutParam5, pictureId);
  SetNumIcons(static_cast<short>(numIcons));
}

// FUNCTION: IMPERIALISM 0x005060c0
void TIconBar::SetPictureResourceIdAndRefresh(short nPictureId, unsigned char fRefreshNow) {
  iconAtlasFrame94 = nPictureId - 700;
  TPicture::SetPictureResourceIdAndRefresh(nPictureId, fRefreshNow);
}

// FUNCTION: IMPERIALISM 0x005060f0
void TIconBar::SetNumIcons(short numIcons) {
  numIcons96 = numIcons;
}

// FUNCTION: IMPERIALISM 0x00506110
void TIconBar::SetNumIcons(short numIcons, unsigned char refreshNow) {
  SetNumIcons(numIcons);
  if (refreshNow != 0) {
    RefreshControl();
  }
}

// Draws numIcons96 copies of the atlas674 icon frame selected by iconAtlasFrame94 evenly spaced
// across the bar's inset content rect (BuildInsetContentRect), dividing the content
// width by (numIcons96+1) ticks and clamping each tick's width to 0x20 (32px). The
// computed tick width is cached in iconSpacing98 for TIconSlider's thumb-position
// helpers.
// FUNCTION: IMPERIALISM 0x00506150
void TIconBar::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CRect contentRect;
  BuildInsetContentRect(&contentRect);

  short slotWidth = static_cast<short>(contentRect.right - contentRect.left) / (numIcons96 + 1);
  if (slotWidth > 0x20) {
    slotWidth = 0x20;
  }
  iconSpacing98 = slotWidth;

  RECT srcRect = {iconAtlasFrame94 * 0x20, 0, iconAtlasFrame94 * 0x20 + 0x20, 0x18};
  RECT dstRect = {contentRect.left, contentRect.top, contentRect.left + 0x20,
                  contentRect.top + 0x18};

  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);
  for (short i = 0; i < numIcons96; ++i) {
    BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    dstRect.left += slotWidth;
    dstRect.right += slotWidth;
  }
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
