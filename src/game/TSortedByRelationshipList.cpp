#include "game/TSortedByRelationshipList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortedByRelationshipList = 0;
}

// FUNCTION: IMPERIALISM 0x004ee4b0
TSortedByRelationshipList* TSortedByRelationshipList::CreateTSortedByRelationshipListInstance() {
  return new TSortedByRelationshipList();
}

// FUNCTION: IMPERIALISM 0x004ee520
void* TSortedByRelationshipList::GetTSortedByRelationshipListClassNamePointer() {
  return &g_pClassDescTSortedByRelationshipList;
}

// FUNCTION: IMPERIALISM 0x004ee540
TSortedByRelationshipList::TSortedByRelationshipList() : TSortedPtrList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004ee570
// TSortedByRelationshipList::`scalar deleting destructor'
