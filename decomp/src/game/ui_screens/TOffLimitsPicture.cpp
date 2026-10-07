#include "game/ui_screens/TOffLimitsPicture.h"

#include "game/ui_core/ScopedMapQuickDrawContext.h"

IMPLEMENT_DYNCREATE(TOffLimitsPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005737d0
TOffLimitsPicture::TOffLimitsPicture() : ownClipRegion(NULL) {}

// FUNCTION: IMPERIALISM 0x00573830
TOffLimitsPicture::~TOffLimitsPicture() {}

// FUNCTION: IMPERIALISM 0x00573850
void TOffLimitsPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  ownClipRegion = NewRgn();
  SetEmptyRgn(ownClipRegion);
}

// FUNCTION: IMPERIALISM 0x00573890
void TOffLimitsPicture::Draw(RECT* rectBuffer) {
  if (ownClipRegion != NULL) {
    GetActiveQuickDrawDc()->SelectClipRgn(&(*ownClipRegion)->rgn, RGN_DIFF);
    TPicture::Draw(rectBuffer);
    GetActiveQuickDrawDc()->SelectClipRgn(0, RGN_COPY);
  }
}

// FUNCTION: IMPERIALISM 0x00573900
void TOffLimitsPicture::Free() {
  DisposeRgn(ownClipRegion);
  ownClipRegion = NULL;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00573940
void TOffLimitsPicture::SetRgn(RgnHandle srcRegion) {
  CopyRgn(srcRegion, ownClipRegion);
}
