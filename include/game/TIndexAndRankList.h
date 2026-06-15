#pragma once

#include "compat.h"
#include "game/CPtrArray.h"

// VTABLE: IMPERIALISM 0x00672eac
class TIndexAndRankList : public CPtrArray {
public:
  TIndexAndRankList();
  // ~TIndexAndRankList is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  // Slot 0 (GetRuntimeClass) and the implicit virtual dtor (slot 1) are the only
  // CObject slots this class overrides; slots 2-4 (Serialize/AssertValidOrSlot0c/
  // DumpOrSlot10) are inherited from CObject unchanged (verified: vtable 0x672eac
  // and CObject 0x66fec4 share 0x404aa7/0x4010a0/0x408625 at slots 2-4).
  virtual CRuntimeClass* GetRuntimeClass() const override;

  // List-operation virtuals introduced by this class (slots 5-16), shared by all
  // derived sorted-list classes — verified identical across vtables 0x659ef0
  // (TSortByPriceList), 0x649068 (TSortedPtrList) and 0x654d38
  // (TSortedByRelationshipList). Bodies are vtable-shape placeholders; the real
  // implementations live at FUN_00488110/00488160/004881f0, but modeling these as
  // real virtuals lets callers dispatch through the native vtable at the correct
  // byte offsets instead of reinterpret_cast'ing to a provisional interface.
  virtual void slot14();                           // 5  (0x14)
  virtual void slot18();                           // 6  (0x18)
  virtual void ResetPtrListRecordsSlot1C();        // 7  (0x1c)
  virtual void slot20();                           // 8  (0x20)
  virtual void ReleaseSlot24();                    // 9  (0x24): list release/free
  virtual void ShrinkCapacitySlot28();             // 10 (0x28)
  virtual void* GetEntrySlot2C(int oneBasedIndex); // 11 (0x2c)
  virtual void RemoveFirstPairSlot30(int mode);    // 12 (0x30)
  virtual void* PeekFirstPairSlot34();             // 13 (0x34)
  virtual void AddEntrySlot38(void* entry);        // 14 (0x38)
  virtual void slot3c();                           // 15 (0x3c)
  virtual void PushPairSlot40(void* pair);         // 16 (0x40)
};

ASSERT_SIZE(TIndexAndRankList, 0x14);
