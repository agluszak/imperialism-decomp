#include "game/TSortedList.h"
#include "game/TMission.h"
#include <new>

IMPLEMENT_DYNCREATE(TSortedList, TObject)

// FUNCTION: IMPERIALISM 0x00487a90
TSortedList* TSortedList::CreateTSortedListInstance() {
  return new TSortedList();
}

// FUNCTION: IMPERIALISM 0x00487b30
int TSortedList::VirtualSlot6C() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487b60
int TSortedList::VirtualSlot70() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487bd0
int TSortedList::VirtualSlot74() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487cc0
int TSortedList::VirtualSlot78() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487d90
int TSortedList::VirtualSlot64() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487dd0
int TSortedList::VirtualSlot68() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004885d0
POSITION TSortedList::AddHeadSlot28(void* item) {
  return this->listState.AddHead(item);
}

// FUNCTION: IMPERIALISM 0x004885f0
POSITION TSortedList::AddHeadSlot2C(void* item, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  return this->listState.AddHead(item);
}

// FUNCTION: IMPERIALISM 0x00488610
POSITION TSortedList::AddTailSlot30(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488630
POSITION TSortedList::AddTailSlot34(void* item, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488650
POSITION TSortedList::AddTailSlot38(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488670
void* TSortedList::RemoveTailSlot3C() {
  return this->listState.RemoveTail();
}

// FUNCTION: IMPERIALISM 0x00488690
POSITION TSortedList::AddTailSlot40(void* item) {
  return this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x004886b0
void* TSortedList::RemoveHeadSlot44() {
  return this->listState.RemoveHead();
}

// FUNCTION: IMPERIALISM TODO
int TSortedList::GetIntByOrdinalSlot24(int ordinal) {
  void* entry = GetEntryByOrdinalSlot4C(ordinal);
  return reinterpret_cast<int>(entry);
}

// FUNCTION: IMPERIALISM 0x004886d0
int TSortedList::GetCountSlot48() {
  return this->listState.GetCount();
}

// FUNCTION: IMPERIALISM 0x004886f0
void* TSortedList::GetEntryByOrdinalSlot4C(int ordinal) {
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  return pos != NULL ? this->listState.GetAt(pos) : 0;
}

// FUNCTION: IMPERIALISM 0x00488720
void TSortedList::RemoveAtOrdinalSlot50(int oneBasedIndex) {
  POSITION pos = this->listState.FindIndex(oneBasedIndex - 1);
  if (pos != 0) {
    this->listState.RemoveAt(pos);
  }
}

// FUNCTION: IMPERIALISM 0x00488750
void TSortedList::FreePayloadsSlot54() {
  if (this->listState.IsEmpty()) {
    return;
  }
  do {
    void* payload = this->listState.RemoveHead();
    if (payload != 0) {
      static_cast<TMission*>(payload)->Free();
    }
  } while (!this->listState.IsEmpty());
}

// FUNCTION: IMPERIALISM 0x00488790
void TSortedList::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x004887b0
void TSortedList::FreePayloadsAndDestroySlot58() {
  this->FreePayloadsSlot54();
  this->Free();
}

// FUNCTION: IMPERIALISM 0x004887e0
void TSortedList::RemoveAllSlot5C() {
  this->listState.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x00488800
void TSortedList::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00488820
void TSortedList::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00488840
void TSortedList::SetAtOrdinalSlot60(int ordinal, void** entryPtr, int unusedFlag) {
  (void)unusedFlag;
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  if (pos != NULL) {
    this->listState.SetAt(pos, *entryPtr);
  }
}

// SYNTHETIC: IMPERIALISM 0x004888f0
// TSortedList::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004a8640
TSortedList::TSortedList() {}

void TSortedList::ConstructTSortedListBaseState(int blockSize) {
  new (&this->listState) CPtrList(blockSize);
}
