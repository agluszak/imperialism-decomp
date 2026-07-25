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

// FUNCTION: IMPERIALISM 0x004ac6c0
TView* TSwapperDaddyView::SelectSwapperItemByTag(int tag) {
  if (tag != selectedTag60) {
    TView* matched = nullptr;
    CSubViewIterator iter(this);
    TView* child = iter.FirstSubView();
    while (iter.MoreSubViews()) {
      if (child->controlTag == tag) {
        CPoint matchLayout(0, 0);
        child->Locate(matchLayout, 1);
        matched = child;
      } else {
        CPoint offscreenLayout(1000, 1000);
        child->Locate(offscreenLayout, 0);
      }
      child = iter.NextSubView();
    }
    selectedTag60 = tag;
    return matched;
  }
  return ResolveControlByTag(tag);
}
