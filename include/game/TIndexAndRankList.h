#pragma once

#include "compat.h"
#include "game/CPtrArray.h"

// VTABLE: IMPERIALISM 0x00672eac
class TIndexAndRankList : public CPtrArray {
public:
  TIndexAndRankList();
  // ~TIndexAndRankList is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  virtual void* GetRuntimeClass();
  virtual int AssertValidOrSlot08();
  virtual void DumpOrSlot0c();
  virtual void SerializeOrSlot10();

  virtual void slot14();
  virtual void slot18();
  virtual void ResetPtrListRecordsSlot1C();
  virtual void slot20();
  virtual void slot24();
  virtual void ShrinkCapacitySlot28();
};

ASSERT_SIZE(TIndexAndRankList, 0x14);
