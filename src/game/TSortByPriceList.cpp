#include "game/TSortByPriceList.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortByPriceList = 0;
}

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 DestructCObArray(void);

// FUNCTION: IMPERIALISM 0x005346f0
void* TSortByPriceList::GetTSortByPriceListClassNamePointer() {
  return &g_pClassDescTSortByPriceList;
}

// FUNCTION: IMPERIALISM 0x00534710
TSortByPriceList::TSortByPriceList() : TIndexAndRankList() {}

// FUNCTION: IMPERIALISM 0x00534740
void* TSortByPriceList::DeletingDestructTSortByPriceList(byte freeSelfFlag) {
  TSortByPriceList* self = this;
  self->DestructTSortByPriceList();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(self)));
  }
  return self;
}

// FUNCTION: IMPERIALISM 0x00534770
void TSortByPriceList::DestructTSortByPriceList() {
  reinterpret_cast<void(__fastcall*)(TIndexAndRankList*)>(::DestructCObArray)(this);
}

// FUNCTION: IMPERIALISM 0x00534680
TSortByPriceList* TSortByPriceList::AllocateAndConstructTSortByPriceList() {
  return new TSortByPriceList();
}

// FUNCTION: IMPERIALISM 0x005347b0
extern "C" int __stdcall CompareSortByPriceListEntriesByField2Ascending(void* a, void* b) {
  short valA = *reinterpret_cast<short*>(reinterpret_cast<char*>(a) + 2);
  short valB = *reinterpret_cast<short*>(reinterpret_cast<char*>(b) + 2);
  if (valA > valB) {
    return 1;
  }
  return -1;
}
