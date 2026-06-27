#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00654d38
class TSortedByRelationshipList : public TSortedPtrList {
public:
  TSortedByRelationshipList();
  DECLARE_DYNCREATE(TSortedByRelationshipList)
  static TSortedByRelationshipList* CreateTSortedByRelationshipListInstance();
};

ASSERT_SIZE(TSortedByRelationshipList, 0x18);
