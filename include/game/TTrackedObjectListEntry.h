#pragma once

#include "compat.h"

// Tracked list node returned from TPtrList::GetEntryByOrdinal (stride matches list engine).
struct TTrackedObjectListEntry {
  void* object;
  unsigned short pad04;
  short regionIndex;
};

ASSERT_SIZE(TTrackedObjectListEntry, 0x08);
