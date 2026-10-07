#pragma once

#include "game/mfc.h"

// The McAppUI live-view registry: every TWindow links itself in on construction and unlinks
// on teardown. CWMgrIterator walks it.

class CWMgrIterator {
public:
  CWMgrIterator* Reset(bool fForward); // (returns this; arg sign-extended)
  void* FirstWindow();
  void* NextWindow();
  int More();

  POSITION nextPosition; // next registry node to visit
  int fForward;          // iteration-direction flag captured by Reset
  void* current;         // current live view (null once past the end)
};
