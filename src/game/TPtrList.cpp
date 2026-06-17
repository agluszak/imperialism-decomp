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
int TPtrList::GetCountOrReleaseSlot28() {
  return *(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10));
}

// FUNCTION: IMPERIALISM 0x004885f0
void* TPtrList::GetNodeByOrdinalSlot2C(int mode, int ordinal) {
  (void)mode;
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  return pos != NULL ? this->listState.GetAt(pos) : 0;
}

// FUNCTION: IMPERIALISM 0x00488610
void TPtrList::AddTail30(void* item) {
  this->listState.AddTail(item);
}

// FUNCTION: IMPERIALISM 0x00488630
void TPtrList::RemoveIntSlot34(int value) {
  this->AddTail30(reinterpret_cast<void*>(value));
}

// FUNCTION: IMPERIALISM 0x00488650
void TPtrList::Call38() {
  this->AddTail30(0);
}

// FUNCTION: IMPERIALISM 0x00488670
void TPtrList::VTableSlot3C_Provisional() {
  this->AddTail30(0);
}

// FUNCTION: IMPERIALISM 0x00488690
void TPtrList::VTableSlot40_Provisional() {
  this->AddTail30(0);
}

// FUNCTION: IMPERIALISM 0x004886b0
void TPtrList::VTableSlot44_Provisional() {
  this->AddTail30(0);
}

// FUNCTION: IMPERIALISM TODO
int TPtrList::GetIntByOrdinalSlot24(int ordinal) {
  void* entry = GetNodeByOrdinalSlot2C(0, ordinal);
  return reinterpret_cast<int>(entry);
}

// FUNCTION: IMPERIALISM 0x004886d0
int TPtrList::GetCountSlot48() {
  return *(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10));
}

// FUNCTION: IMPERIALISM 0x004886f0
void* TPtrList::GetTrackedEntrySlot4C(int ordinal) {
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  return pos != NULL ? this->listState.GetAt(pos) : 0;
}

// FUNCTION: IMPERIALISM 0x00488720
void TPtrList::RemoveEntryAtSlot50(int oneBasedIndex) {
  POSITION pos = this->listState.FindIndex(oneBasedIndex - 1);
  if (pos != 0) {
    this->listState.RemoveAt(pos);
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
      static_cast<TTrackedObject*>(payload)->Free();
    }
  } while (*(reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x10)) != 0);
}

// FUNCTION: IMPERIALISM 0x00488790
void TPtrList::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x004887b0
void TPtrList::Call58() {
  this->Call54();
  this->Free();
}

// FUNCTION: IMPERIALISM 0x004887e0
void TPtrList::VTableSlot5C_Provisional() {}

// FUNCTION: IMPERIALISM 0x00488800
void TPtrList::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x00488820
void TPtrList::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x00488840
void TPtrList::SetEntryDataAtSlot60(int ordinal, void** entryPtr, int unusedFlag) {
  (void)unusedFlag;
  POSITION pos = this->listState.FindIndex(ordinal - 1);
  if (pos != NULL) {
    this->listState.SetAt(pos, *entryPtr);
  }
}

// Destructor is compiler-generated; the implicit ~TPtrList destroys the embedded
// listState (CPtrList).
