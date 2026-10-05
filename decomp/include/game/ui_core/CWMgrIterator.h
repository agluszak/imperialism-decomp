#pragma once

#include "game/mfc.h"

// The McAppUI live-view registry: every TWindow links itself in on construction (inline
// AddHead) and unlinks on teardown. A CList<TWindow*, TWindow*>, base 0x006a1a40 (vtable
// 0x0064b580), shared with the modal stack. Iterated through CWMgrIterator below.
// g_LiveViewRegistry — see game/globals/view_registries.h.

class CWMgrIterator {
public:
  CWMgrIterator* Reset(bool fForward); // 0x004923f0 (returns this; arg sign-extended)
  void* FirstWindow();                 // 0x00492440
  void* NextWindow();                  // 0x00492470
  int More();                          // 0x004924a0

  POSITION nextPosition; // +0x00 — next registry node to visit
  int fForward;          // +0x04 — iteration-direction flag captured by Reset
  void* current;         // +0x08 — current live view (null once past the end)
};
