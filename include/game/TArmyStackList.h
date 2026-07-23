#pragma once

#include "game/TSortedList.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c9a0
class TArmyStackList : public TSortedList {
public:
  DECLARE_DYNCREATE(TArmyStackList)
  virtual ~TArmyStackList() override; // slot 0x01 (scalar deleting destructor)
  // Descending three-way compare of the short at +0x6 of each payload (stack-size
  // ordering). The payload type cannot be read off this class: Compare is reached only
  // through vtable slot 0x1b, so it has to come from whoever inserts into the list
  // (see the focused follow-up bead).
  short Compare(void* a, void* b) override; // slot 0x1b byte 0x6c 0x4a8560

  TArmyStackList();
};
