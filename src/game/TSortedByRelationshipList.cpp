#include "game/TSortedByRelationshipList.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortedByRelationshipList = 0;
}

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 DestructCObArray(void);

// FUNCTION: IMPERIALISM 0x004ee520
void* TSortedByRelationshipList::GetTSortedByRelationshipListClassNamePointer() {
  return &g_pClassDescTSortedByRelationshipList;
}

// FUNCTION: IMPERIALISM 0x004ee540
TSortedByRelationshipList* TSortedByRelationshipList::ConstructObArrayWithVtable654D38() {
  this->TIndexAndRankList::TIndexAndRankList();
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTSortedByRelationshipList);
  return this;
}

// FUNCTION: IMPERIALISM 0x004ee570
void* TSortedByRelationshipList::DestructTSortedByRelationshipListAndMaybeFree(byte freeSelfFlag) {
  TSortedByRelationshipList* self = this;
  reinterpret_cast<void(__fastcall*)(TIndexAndRankList*)>(::DestructCObArray)(self);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(self)));
  }
  return self;
}

// FUNCTION: IMPERIALISM 0x004ee4b0
TSortedByRelationshipList* TSortedByRelationshipList::CreateTSortedByRelationshipListInstance() {
  return new TSortedByRelationshipList();
}
