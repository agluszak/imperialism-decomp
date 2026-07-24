#include "game/military_ui/TSwapperDaddyView.h"

#include "game/CSubViewIterator.h"
// SYNTHETIC: IMPERIALISM 0x004ac5c0
// TSwapperDaddyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ac650
// TSwapperDaddyView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004ac680
TSwapperDaddyView::~TSwapperDaddyView() {}

// SYNTHETIC: IMPERIALISM 0x004ac6a0
// TSwapperDaddyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSwapperDaddyView, TView)

// NOOP: verified empty in original 0x004ac5f5 (no standalone TSwapperDaddyView::TSwapperDaddyView body exists: CreateObject 0x004ac5c0 inlines this default ctor, calling the TView base ctor directly at that site)
TSwapperDaddyView::TSwapperDaddyView() {}

// FUNCTION: IMPERIALISM 0x004ac6c0
TView* TSwapperDaddyView::SelectSwapperItemByTag(int tag) {
  if (tag != selectedTag60) {
    TView* matched = nullptr;
    CSubViewIterator iter(this);
    TView* child = iter.FirstSubView();
    while (iter.MoreSubViews()) {
      if (child->controlTag == tag) {
        int matchLayout[2] = {0, 0};
        child->CaptureLayoutF0(matchLayout, 1);
        matched = child;
      } else {
        int offscreenLayout[2] = {1000, 1000};
        child->CaptureLayoutF0(offscreenLayout, 0);
      }
      child = iter.NextSubView();
    }
    selectedTag60 = tag;
    return matched;
  }
  return ResolveControlByTag(tag);
}
