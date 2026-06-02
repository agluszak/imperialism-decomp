#pragma once

#include "game/TSortedPtrList.h"

extern "C" char g_vtblTSortedByRelationshipList;

// VTABLE: IMPERIALISM 0x00654d38
class TSortedByRelationshipList : public TSortedPtrList {
 public:
  TSortedByRelationshipList() : TSortedPtrList() {
    *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTSortedByRelationshipList);
  }
  virtual ~TSortedByRelationshipList() {}

  static void* GetTSortedByRelationshipListClassNamePointer();
  static TSortedByRelationshipList* CreateTSortedByRelationshipListInstance();
  TSortedByRelationshipList* ConstructObArrayWithVtable654D38();
  void* DestructTSortedByRelationshipListAndMaybeFree(byte freeSelfFlag);
};

typedef char TSortedByRelationshipListSizeMustMatch[
    (sizeof(TSortedByRelationshipList) == 0x18) ? 1 : -1];
