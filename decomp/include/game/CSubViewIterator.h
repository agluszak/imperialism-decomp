#pragma once

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"

class CSubViewIterator {
public:
  CSubViewIterator(const TView* owner); // (default forward)
  CSubViewIterator(const TView* owner, char forward);
  TView* FirstSubView();
  TView* NextSubView();
  int MoreSubViews();

  POSITION position;      // current CList position (node)
  const TView* ownerView; // view whose childList is walked
  int direction;          // 1 = forward from head, 0 = reverse from tail
  int identTag;           // subview identifier filter, "    " ('    ') = no filter
  TView* currentChild;    // payload of the current node (validity field)
};
