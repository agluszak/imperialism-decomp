#include "game/TPtrList.h"
#include "game/TTrackedObject.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTPtrList = 0;
}

void* TPtrList::GetTPtrListClassNamePointer() {
  return &g_pClassDescTPtrList;
}

void TPtrList::ConstructTPtrListBaseState(int ownerContext) {
  new (&this->listState) CPtrList(ownerContext);
}

// FUNCTION: IMPERIALISM 0x004885d0
POSITION TPtrList::AddHeadSlot28(void* item) {
  return this->listState.AddHead(item);
}

// FUNCTION: IMPERIALISM 0x004885f0
POSITION TPtrList::AddHeadSlot2C(void* item, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  return this->listState.AddHead(item);
}

// FUNCTION: IMPERIALISM 0x00488610
POSITION TPtrList::AddTailSlot30(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488630
POSITION TPtrList::AddTailSlot34(void* item, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488650
POSITION TPtrList::AddTailSlot38(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488670
void* TPtrList::RemoveTailSlot3C() {
  return this->listState.RemoveTail();
}

// FUNCTION: IMPERIALISM 0x00488690
POSITION TPtrList::AddTailSlot40(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x004886b0
void* TPtrList::RemoveHeadSlot44() {
  return this->listState.RemoveHead();
}

// FUNCTION: IMPERIALISM TODO
int TPtrList::GetIntByOrdinalSlot24(int ordinal) {
  void* entry = GetEntryByOrdinalSlot4C(ordinal);
  return reinterpret_cast<int>(entry);
}

// FUNCTION: IMPERIALISM 0x004886d0
int TPtrList::GetCountSlot48() {
  return this->listState.GetCount();
}

// FUNCTION: IMPERIALISM 0x004886f0
void* TPtrList::GetEntryByOrdinalSlot4C(int ordinal) {
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  return pos != NULL ? this->listState.GetAt(pos) : 0;
}

// FUNCTION: IMPERIALISM 0x00488720
void TPtrList::RemoveAtOrdinalSlot50(int oneBasedIndex) {
  POSITION pos = this->listState.FindIndex(oneBasedIndex - 1);
  if (pos != 0) {
    this->listState.RemoveAt(pos);
  }
}

// FUNCTION: IMPERIALISM 0x00488750
void TPtrList::FreePayloadsSlot54() {
  if (this->listState.IsEmpty()) {
    return;
  }
  do {
    void* payload = this->listState.RemoveHead();
    if (payload != 0) {
      static_cast<TTrackedObject*>(payload)->Free();
    }
  } while (!this->listState.IsEmpty());
}

// FUNCTION: IMPERIALISM 0x00488790
void TPtrList::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x004887b0
void TPtrList::FreePayloadsAndDestroySlot58() {
  this->FreePayloadsSlot54();
  this->Free();
}

// FUNCTION: IMPERIALISM 0x004887e0
void TPtrList::RemoveAllSlot5C() {
  this->listState.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x00488800
void TPtrList::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00488820
void TPtrList::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00488840
void TPtrList::SetAtOrdinalSlot60(int ordinal, void** entryPtr, int unusedFlag) {
  (void)unusedFlag;
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  if (pos != NULL) {
    this->listState.SetAt(pos, *entryPtr);
  }
}

// FUNCTION: IMPERIALISM 0x00487d90
int TPtrList::VirtualSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487dd0
int TPtrList::VirtualSlot68() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487b30
int TPtrList::VirtualSlot6C() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487b60
int TPtrList::VirtualSlot70() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487bd0
int TPtrList::VirtualSlot74() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487cc0
int TPtrList::VirtualSlot78() {
  return 0;
}

// Destructor is compiler-generated; the implicit ~TPtrList destroys the embedded
// listState (CPtrList).
