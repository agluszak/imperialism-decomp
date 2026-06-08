#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00654d38
class TSortedByRelationshipList : public TSortedPtrList {
public:
  TSortedByRelationshipList();
  virtual ~TSortedByRelationshipList();

  static void* GetTSortedByRelationshipListClassNamePointer();
  static TSortedByRelationshipList* CreateTSortedByRelationshipListInstance();
  TSortedByRelationshipList* ConstructObArrayWithVtable654D38();
  void* DestructTSortedByRelationshipListAndMaybeFree(byte freeSelfFlag);
};

ASSERT_SIZE(TSortedByRelationshipList, 0x18);
