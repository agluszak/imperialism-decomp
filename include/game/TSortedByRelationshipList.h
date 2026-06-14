#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00654d38
struct CRuntimeClass;
class TSortedByRelationshipList : public TSortedPtrList {
public:
  TSortedByRelationshipList();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor).
  static TSortedByRelationshipList* CreateTSortedByRelationshipListInstance();
};

ASSERT_SIZE(TSortedByRelationshipList, 0x18);
