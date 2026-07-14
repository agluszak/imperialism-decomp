#pragma once

#include "game/TView.h"

// Bidirectional stack cursor over a TView's childList44 (CList<TView*, TView*>). Ghidra
// names it after the SelectableTextOptionEntry callers (TRadioTextCluster /
// TSwapperDaddyView option handling), but it is a generic TView child-list cursor: the
// same shape as CIterator (Reset/More/Advance) plus a reverse-traversal flag and a 4-char
// filter tag. The traversal is plain MFC CList: GetHeadPosition/GetTailPosition seed the
// position and GetNext/GetPrev read the node payload while advancing. Initialize returns
// `this` and Begin/Advance return the current child so call sites read the payload from the
// call result (piVar2 = Begin(); ...; piVar2 = Advance();). reccmp pairs the four methods
// by address (definitions in TTurnEventDialogFactoryRegistry.cpp, the owning TU).
struct TSelectableTextOptionEntryIterator {
  POSITION position00;   // +0x00 current CList position (node)
  TView* ownerView04;    // +0x04 view whose childList44 is walked
  int direction08;       // +0x08 1 = forward from head, 0 = reverse from tail
  int tag0c;             // +0x0c 4-char filter tag, initialised to "    " (0x20202020)
  TView* currentChild10; // +0x10 payload of the current node (validity field)

  TSelectableTextOptionEntryIterator* Initialize(TView* owner); // 0x004919a0
  TView* Begin();                                               // 0x00491a00
  TView* Advance();                                             // 0x00491a70
  int IsValid();                                                // 0x00491ab0
};
