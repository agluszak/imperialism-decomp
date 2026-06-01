#include "game/TSortedPtrList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortedPtrList = 0;
}

int AllocateWithFallbackHandler(undefined4 size_bytes);

namespace {

const unsigned int kAddrVtblGenericPtrList = 0x00649068;

} // namespace

// FUNCTION: IMPERIALISM 0x00407DA6
void __fastcall thunk_ResetPtrListAndShrinkCapacity(TSortedPtrList* self) {
  self->ResetPtrListAndShrinkCapacity();
}

// FUNCTION: IMPERIALISM 0x00409868
void* __fastcall thunk_GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int unusedEdx,
                                                      int oneBasedIndex) {
  return GetPtrListEntryByOneBasedIndex(self, unusedEdx, oneBasedIndex);
}

// FUNCTION: IMPERIALISM 0x004883E0
void* TSortedPtrList::GetTSortedPtrListClassNamePointer() {
  return &g_pClassDescTSortedPtrList;
}

// FUNCTION: IMPERIALISM 0x00488400
TSortedPtrList* TSortedPtrList::ConstructTSortedPtrListBaseState() {
  TSortedPtrList* list = reinterpret_cast<TSortedPtrList*>(AllocateWithFallbackHandler(0x18));
  if (list != 0) {
    list->CPtrArray();
    *reinterpret_cast<void**>(list) = reinterpret_cast<void*>(kAddrVtblGenericPtrList);
  }
  return list;
}

// FUNCTION: IMPERIALISM 0x00488110
void TSortedPtrList::ResetPtrListAndShrinkCapacity() {
  this->ResetPtrListRecordsSlot1C();
  this->ShrinkCapacitySlot28();
}

// FUNCTION: IMPERIALISM 0x00488160
void* __fastcall GetPtrListEntryByOneBasedIndex(TSortedPtrList* self, int, int oneBasedIndex) {
  if (oneBasedIndex <= self->count) {
    return self->entries[oneBasedIndex - 1];
  }
  return 0;
}

void* TSortedPtrList::GetPtrListEntryByOneBasedIndex(int oneBasedIndex) {
  return ::GetPtrListEntryByOneBasedIndex(this, 0, oneBasedIndex);
}
