#include "game/TIndexAndRankList.h"

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 DestructCObArray(void);

// FUNCTION: IMPERIALISM 0x00601baa
TIndexAndRankList::TIndexAndRankList() : CPtrArray() {}

// FUNCTION: IMPERIALISM 0x00601bc1
void* TIndexAndRankList::DestructCObArrayAndMaybeFree(byte freeSelfFlag) {
  TIndexAndRankList* self = this;
  reinterpret_cast<void(__fastcall*)(TIndexAndRankList*)>(::DestructCObArray)(self);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(self)));
  }
  return self;
}

TIndexAndRankList::~TIndexAndRankList() {}

void* TIndexAndRankList::GetRuntimeClass() {
  return 0;
}
int TIndexAndRankList::AssertValidOrSlot08() {
  return 0;
}
void TIndexAndRankList::DumpOrSlot0c() {}
void TIndexAndRankList::SerializeOrSlot10() {}

void TIndexAndRankList::slot14() {}
void TIndexAndRankList::slot18() {}
void TIndexAndRankList::ResetPtrListRecordsSlot1C() {}
void TIndexAndRankList::slot20() {}
void TIndexAndRankList::slot24() {}
void TIndexAndRankList::ShrinkCapacitySlot28() {}
