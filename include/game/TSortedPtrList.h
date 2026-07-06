#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CPtrArray.h"
#include "game/mfc.h"

struct CRuntimeClass;

// CPtrArray-derived sorted pointer list base (vtable 0x00649010, GetRuntimeClass
// 0x004883e0 returns the "TSortedPtrList" CRuntimeClass descriptor). The derived
// TPtrList owns vtable 0x00649068.
// Base recovered from CRuntimeClass descriptor: TSortedPtrList -> CPtrArray -> CObject.
// VTABLE: IMPERIALISM 0x00649010
class TSortedPtrList : public CPtrArray {
public:
  DECLARE_DYNCREATE(TSortedPtrList)

  short relationType; // +0x14
  short pad16;        // +0x16

  TSortedPtrList();
  virtual ~TSortedPtrList();

  // List-operation virtuals introduced by TSortedPtrList (slots 5-16):
  virtual void slot14(void* message = 0);          // 5  (0x14)
  virtual void slot18();                           // 6  (0x18)
  virtual void ResetPtrListRecordsSlot1C();        // 7  (0x1c)
  virtual void slot20();                           // 8  (0x20)
  virtual void ReleaseSlot24();                    // 9  (0x24)
  virtual void SelfDeleteSlot28();                 // 10 (0x28) if (this) delete this;
  virtual void* GetEntrySlot2C(int oneBasedIndex); // 11 (0x2c)
  virtual void RemoveFirstPairSlot30(int mode);    // 12 (0x30)
  virtual void* PeekFirstPairSlot34();             // 13 (0x34)
  virtual void AddEntrySlot38(void* entry);        // 14 (0x38)
  virtual void slot3c();                           // 15 (0x3c)
  virtual void PushPairSlot40(void* pair);         // 16 (0x40)

  static TSortedPtrList* ConstructTSortedPtrListBaseState();
};

ASSERT_SIZE(TSortedPtrList, 0x18);
