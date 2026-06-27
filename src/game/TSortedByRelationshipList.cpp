#include "game/TSortedByRelationshipList.h"
#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x004ee4b0
TSortedByRelationshipList* TSortedByRelationshipList::CreateTSortedByRelationshipListInstance() {
  return new TSortedByRelationshipList();
}
IMPLEMENT_DYNCREATE(TSortedByRelationshipList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x004ee540
TSortedByRelationshipList::TSortedByRelationshipList() : TSortedPtrList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004ee570
// TSortedByRelationshipList::`scalar deleting destructor'
