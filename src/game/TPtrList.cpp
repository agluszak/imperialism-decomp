#include "game/TPtrList.h"
#include "game/TTrackedObject.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTPtrList = 0;
}

// FUNCTION: IMPERIALISM 0x00488510
void* TPtrList::GetTPtrListClassNamePointer() {
  return &g_pClassDescTPtrList;
}

void TPtrList::ConstructTPtrListBaseState(int ownerContext) {
  new (&this->listState) CPtrList(ownerContext);
}

// FUNCTION: IMPERIALISM 0x004885d0
int TPtrList::GetCountOrReleaseSlot28() {
  return *(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10));
}

// FUNCTION: IMPERIALISM 0x004885f0
void* TPtrList::GetNodeByOrdinalSlot2C(int mode, int ordinal) {
  (void)mode;
  return this->listState.GetDataAtOneBasedIndex(ordinal);
}

// FUNCTION: IMPERIALISM 0x00488610
void TPtrList::AddTail30(void* item) {
  this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x004886d0
int TPtrList::GetCountSlot48() {
  return *(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10));
}

// FUNCTION: IMPERIALISM 0x004886f0
void* TPtrList::GetTrackedEntrySlot4C(int ordinal) {
  return this->listState.GetDataAtOneBasedIndex(ordinal);
}

// FUNCTION: IMPERIALISM 0x00488720
void TPtrList::RemoveEntryAtSlot50(int oneBasedIndex) {
  CPtrListNode* node = this->listState.GetNodeAtZeroBasedIndex(oneBasedIndex - 1);
  if (node != 0) {
    this->listState.RemoveAt(node);
  }
}

// FUNCTION: IMPERIALISM 0x00488750
void TPtrList::Call54() {
  if (*(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10)) == 0) {
    return;
  }
  do {
    void* payload = this->listState.RemoveHead();
    if (payload != 0) {
      static_cast<TTrackedObject*>(payload)->Release1C();
    }
  } while (*(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10)) != 0);
}

// FUNCTION: IMPERIALISM 0x00488790
void TPtrList::Release1C() {
  this->DeleteSelfSlot04(1);
}

// FUNCTION: IMPERIALISM 0x004887b0
void TPtrList::Call58() {
  this->Call54();
  this->Release1C();
}

// FUNCTION: IMPERIALISM 0x00488840
void TPtrList::SetEntryDataAtSlot60(int ordinal, void** entryPtr, int unusedFlag) {
  (void)unusedFlag;
  CPtrListNode* node = this->listState.GetNodeAtZeroBasedIndex(ordinal - 1);
  if (node != 0) {
    node->data = *entryPtr;
  }
}

// Destructor is compiler-generated; the implicit ~TPtrList destroys the embedded
// listState (CPtrList).
