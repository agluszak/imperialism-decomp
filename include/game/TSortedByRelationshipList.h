#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x00654d38
class TSortedByRelationshipList : public TSortedPtrList {
public:
  TSortedByRelationshipList();
  DECLARE_DYNCREATE(TSortedByRelationshipList)
  // Descending by the relationship short at record+2; ties broken pseudo-randomly.
  short Compare(void* a, void* b) override; // slot 0x44 0x4ee5e0
  // 0x004ee5c0 — recordSize14 = 4 (same shape as TProvinceDesirabilityList's
  // InitializeProvinceRecordSize); callers invoke it right after construction.
  void InitializeRelationshipRecordSize();
};

ASSERT_SIZE(TSortedByRelationshipList, 0x18);
