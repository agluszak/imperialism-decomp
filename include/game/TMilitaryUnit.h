#pragma once

#include "compat.h"
#include "game/CString.h"

// Military unit list entry (militaryUnitList44 / CIterator walk).
class TMilitaryUnit {
public:
  short pad00[2];
  short unitTypeId04; // 0x04
  unsigned char pad06[0x1a - 0x06];
  short nameTag1a; // 0x1a — 0 means unnamed (slot 0x0f naming pass)
  unsigned char pad1c[0x24 - 0x1c];
  CString displayName24; // 0x24
};
