#include "game/military_ui/TSwapperDaddyView.h"

#include "game/CSubViewIterator.h"

// FUNCTION: IMPERIALISM 0x004ac680
TSwapperDaddyView::~TSwapperDaddyView() {}

IMPLEMENT_DYNCREATE(TSwapperDaddyView, TView)

// FUNCTION: IMPERIALISM 0x004ac6c0
TView* TSwapperDaddyView::SelectSwapperItemByTag(int tag) {
  if (tag != selectedTag) {
    TView* matched = NULL;
    CSubViewIterator iter(this);
    TView* child = iter.FirstSubView();
    while (iter.MoreSubViews()) {
      if (child->controlTag == tag) {
        CPoint matchLayout(0, 0);
        child->Locate(matchLayout, true);
        matched = child;
      } else {
        CPoint offscreenLayout(1000, 1000);
        child->Locate(offscreenLayout, false);
      }
      child = iter.NextSubView();
    }
    selectedTag = tag;
    return matched;
  }
  return FindSubView(tag);
}
