#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00654d38
class TSortedByRelationshipList : public TSortedPtrList {
public:
  TSortedByRelationshipList();
  // Destructor is compiler-generated (implicit virtual dtor).

  static void* GetTSortedByRelationshipListClassNamePointer();
  static TSortedByRelationshipList* CreateTSortedByRelationshipListInstance();
};

ASSERT_SIZE(TSortedByRelationshipList, 0x18);
