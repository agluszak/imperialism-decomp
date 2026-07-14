#include "game/TSwapperDaddyView.h"

#include "game/TSelectableTextOptionEntryIterator.h"

// FUNCTION: IMPERIALISM 0x004ac6c0
TView* TSwapperDaddyView::SelectSwapperItemByTag(unsigned int tag) {
  if (tag != static_cast<unsigned int>(selectedTag60)) {
    TView* matched = nullptr;
    TSelectableTextOptionEntryIterator iter;
    iter.Initialize(this);
    TView* child = iter.Begin();
    while (iter.IsValid()) {
      if (child->controlTag == tag) {
        int matchLayout[2] = {0, 0};
        child->CaptureLayoutF0(matchLayout, 1);
        matched = child;
      } else {
        int offscreenLayout[2] = {1000, 1000};
        child->CaptureLayoutF0(offscreenLayout, 0);
      }
      child = iter.Advance();
    }
    selectedTag60 = tag;
    return matched;
  }
  return ResolveControlByTag(tag);
}

// SYNTHETIC: IMPERIALISM 0x004ac650
// TSwapperDaddyView::`scalar deleting destructor'
TSwapperDaddyView::~TSwapperDaddyView() {}
// SYNTHETIC: IMPERIALISM 0x004ac5c0
// TSwapperDaddyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ac6a0
// TSwapperDaddyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSwapperDaddyView, TView)

TSwapperDaddyView::TSwapperDaddyView() {}
