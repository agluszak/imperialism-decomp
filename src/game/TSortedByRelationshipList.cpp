#include "game/TSortedByRelationshipList.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x004ee4b0
// TSortedByRelationshipList::CreateObject
// SYNTHETIC: IMPERIALISM 0x004ee520
// TSortedByRelationshipList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSortedByRelationshipList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x004ee540
TSortedByRelationshipList::TSortedByRelationshipList() : TSortedPtrList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004ee570
// TSortedByRelationshipList::`scalar deleting destructor'

// Not-yet-recovered free functions this file calls into.
extern undefined4 GenerateThreadLocalRandom15(void);

// FUNCTION: IMPERIALISM 0x004ee5e0
short TSortedByRelationshipList::Compare(void* a, void* b) {
  short aKey = *reinterpret_cast<short*>(static_cast<char*>(a) + 2);
  short bKey = *reinterpret_cast<short*>(static_cast<char*>(b) + 2);
  if (bKey < aKey) {
    return 1;
  }
  if (aKey < bKey) {
    return -1;
  }
  return static_cast<short>(static_cast<int>(GenerateThreadLocalRandom15()) % 2 != 0 ? 1 : -1);
}
