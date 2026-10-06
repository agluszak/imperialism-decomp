#pragma once

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"

class CSubViewIterator {
public:
  CSubViewIterator(const TView* owner); // 0x004919a0 (default forward)
  CSubViewIterator(const TView* owner, char forward);
  TView* FirstSubView(); // 0x00491a00
  TView* NextSubView();  // 0x00491a70
  int MoreSubViews();    // 0x00491ab0

  POSITION position00;    // +0x00 current CList position (node)
  const TView* ownerView; // +0x04 view whose childList is walked
  int direction;          // +0x08 1 = forward from head, 0 = reverse from tail
  int identTag;           // +0x0c subview identifier filter, "    " ('    ') = no filter
  TView* currentChild;    // +0x10 payload of the current node (validity field)
};
