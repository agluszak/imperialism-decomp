#pragma once

#include "compat.h"

// Military unit list entry (militaryUnitList44 / CIterator walk).
// Full class recovery pending; layout through +0x06 matches Ghidra TMilitaryUnit ctor.
class TMilitaryUnit {
public:
  short pad00[2];
  short unitTypeId04;
};
