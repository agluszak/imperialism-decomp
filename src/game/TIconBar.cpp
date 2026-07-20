#include "game/TIconBar.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x00505f50
// TIconBar::CreateObject

// SYNTHETIC: IMPERIALISM 0x00505fd0
// TIconBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIconBar, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00505ff0
TIconBar::TIconBar() : TNoHilitePicture() {}

// SYNTHETIC: IMPERIALISM 0x00506020
// TIconBar::`scalar deleting destructor'
TIconBar::~TIconBar() {}

// FUNCTION: IMPERIALISM 0x005060c0
void TIconBar::SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) {
  field94 = nPictureId - 700;
  TPicture::SetPictureResourceIdAndRefresh(nPictureId, fRefreshNow);
}

// FUNCTION: IMPERIALISM 0x005060f0
undefined TIconBar::OrphanTiny_SetWordEcxOffset_96_005060f0(undefined2 param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00506110
undefined TIconBar::OrphanCallChain_C2_I15_00506110(char param_1) {
  return 0;
}

// Draws field96 copies of the atlas674 icon frame selected by field94 evenly spaced
// across the bar's inset content rect (BuildInsetContentRect), dividing the content
// width by (field96+1) ticks and clamping each tick's width to 0x20 (32px). The
// computed tick width is cached in tickSlotWidth98 for TIconSlider's thumb-position
// helpers.
// FUNCTION: IMPERIALISM 0x00506150
void TIconBar::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  RECT contentRect;
  BuildInsetContentRect(&contentRect);

  short slotWidth = static_cast<short>(contentRect.right - contentRect.left) / (field96 + 1);
  if (slotWidth > 0x20) {
    slotWidth = 0x20;
  }
  tickSlotWidth98 = slotWidth;

  RECT srcRect = {field94 * 0x20, 0, field94 * 0x20 + 0x20, 0x18};
  RECT dstRect = {contentRect.left, contentRect.top, contentRect.left + 0x20,
                  contentRect.top + 0x18};

  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);
  for (short i = 0; i < field96; ++i) {
    BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    dstRect.left += slotWidth;
    dstRect.right += slotWidth;
  }
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
