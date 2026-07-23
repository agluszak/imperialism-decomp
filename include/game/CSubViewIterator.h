#pragma once

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"

// MacApp CSubViewIterator (Mac CodeWarrior oracle: constructors (TView*, unsigned char) and
// (const TView*), FirstSubView(), NextSubView(), ~CSubViewIterator()). A stack cursor over a
// TView's childList44 (MFC CList<TView*, TView*>): it walks forward from the head or in
// reverse from the tail per the direction byte, using GetNext/GetPrev to read the current
// child's payload while advancing the position. The single-arg constructor at 0x004919a0
// defaults the direction to forward and sets the identifier filter to "    " (no filter).
// The Windows port carries an explicit MoreSubViews() validity check; the Mac loop instead
// tests FirstSubView()/NextSubView()'s returned TView* against nil. reccmp pairs the four
// members by address (definitions in TTurnEventDialogFactoryRegistry.cpp, the owning TU).
class CSubViewIterator {
public:
  CSubViewIterator(const TView* owner); // 0x004919a0 (default forward)
  TView* FirstSubView();                // 0x00491a00
  TView* NextSubView();                 // 0x00491a70
  int MoreSubViews();                   // 0x00491ab0

  POSITION position00;      // +0x00 current CList position (node)
  const TView* ownerView04; // +0x04 view whose childList44 is walked
  int direction08;          // +0x08 1 = forward from head, 0 = reverse from tail
  int identTag0c;           // +0x0c subview identifier filter, "    " ('    ') = no filter
  TView* currentChild10;    // +0x10 payload of the current node (validity field)
};
