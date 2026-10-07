#pragma once

#include "game/mfc.h"

// The McAppUI live-view registry: every TWindow links itself in on construction and unlinks
// on teardown. CWMgrIterator walks it.

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
