#pragma once

#include "game/mfc.h"

// The McAppUI live-view registry: every TWindow/TView links itself in on construction
// (inline AddHead) and unlinks on teardown. An MFC CPtrList, base 0x006a1a40
// (vtable 0x0064b580). Iterated through TUiWindowTraversal below.
extern CPtrList g_LiveViewRegistry;

// 12-byte stack cursor over g_LiveViewRegistry, used to sweep every live UI window/view
// (e.g. TDisplayMgr::DispatchUiWindowStatusTickForClass99Windows). Reset() arms it,
// LoadFirst()/LoadNext() walk the registry, IsValid() reports whether the current node
// still holds an entry.
class TUiWindowTraversal {
public:
  void Reset(char mode); // 0x004923f0
  void* LoadFirst();     // 0x00492440
  void* LoadNext();      // 0x00492470
  int IsValid();         // 0x004924a0

  POSITION nextPosition; // +0x00 — next registry node to visit
  int traversalMode;     // +0x04 — mode flag captured by Reset
  void* current;         // +0x08 — current live view (null once past the end)
};
