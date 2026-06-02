#include "game/TIndexAndRankList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 DestructCObArray(void);
void FreeHeapBufferIfNotNull(undefined4 ptrValue);

extern "C" {
char g_vtblTIndexAndRankList = 0;
}

// FUNCTION: IMPERIALISM 0x00601BAA
TIndexAndRankList* TIndexAndRankList::CPtrArray() {
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblTIndexAndRankList);
  this->entries = 0;
  this->growBy = 0;
  this->capacity = 0;
  this->count = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00601BC1
void* TIndexAndRankList::DestructCObArrayAndMaybeFree(byte freeSelfFlag) {
  TIndexAndRankList* self = this;
  reinterpret_cast<void(__fastcall*)(TIndexAndRankList*)>(::DestructCObArray)(self);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(self)));
  }
  return self;
}
