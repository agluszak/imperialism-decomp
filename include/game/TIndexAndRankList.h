#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00659c58
class TIndexAndRankList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TIndexAndRankList)

  TIndexAndRankList();
  // ~TIndexAndRankList is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  // Overrides of TSortedPtrList's list-operation virtuals (slots 5-16):
  virtual void slot14(void* message = 0) override;
  virtual void slot18() override;
  virtual void ResetPtrListRecordsSlot1C() override;
  virtual void slot20() override;
  virtual void ReleaseSlot24() override;
  virtual void ShrinkCapacitySlot28() override;
  virtual void* GetEntrySlot2C(int oneBasedIndex) override;
  virtual void RemoveFirstPairSlot30(int mode) override;
  virtual void* PeekFirstPairSlot34() override;
  virtual void AddEntrySlot38(void* entry) override;
  virtual void slot3c() override;
  virtual void PushPairSlot40(void* pair) override;
};

ASSERT_SIZE(TIndexAndRankList, 0x18);
