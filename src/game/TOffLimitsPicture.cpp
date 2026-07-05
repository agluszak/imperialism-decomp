#include "game/TOffLimitsPicture.h"
// SYNTHETIC: IMPERIALISM 0x00573710
// TOffLimitsPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005737b0
// TOffLimitsPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOffLimitsPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005737d0
TOffLimitsPicture::TOffLimitsPicture() : TPicture(), ownClipRegion90(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x00573800
// TOffLimitsPicture::`scalar deleting destructor'
TOffLimitsPicture::~TOffLimitsPicture() {}

// FUNCTION: IMPERIALISM 0x00573850
void TOffLimitsPicture::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
  ownClipRegion90 = NewRgn();
  SetEmptyRgn(ownClipRegion90);
}

// FUNCTION: IMPERIALISM 0x00573890
void TOffLimitsPicture::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00573900
void TOffLimitsPicture::Free() {
  DisposeRgn(ownClipRegion90);
  ownClipRegion90 = nullptr;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00573940
undefined TOffLimitsPicture::ForwardCopyRgn(
    RgnHandle srcRegion) {
  CopyRgn(srcRegion, ownClipRegion90);
  return 0;
}
