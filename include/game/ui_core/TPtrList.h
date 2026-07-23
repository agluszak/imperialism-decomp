#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/mfc.h"

class TStream;

// CPtrArray-derived by-value record list leaf. The real vtable (0x00649068, 19 slots
// 0x00-0x48) inherits every TSortedPtrList slot unchanged and adds exactly one
// virtual; the previously modelled parallel-to-TSortedList slot set (0x4c-0x78) does
// not exist in the original vtable.
// Base recovered from CRuntimeClass descriptor: TPtrList -> TSortedPtrList -> CPtrArray -> CObject.
// VTABLE: IMPERIALISM 0x00649068
class TPtrList : public TSortedPtrList {
public:
  // FUNCTION: IMPERIALISM 0x004884f0
  ~TPtrList() override {}
  DECLARE_DYNCREATE(TPtrList)
  TPtrList();

  // Same copy-to-front behavior as inherited slot 0x40, exposed by TPtrList as its
  // own final virtual slot.
  virtual void PrependCopiedRecordToPtrList(void* record); // slot 0x48 0x488470

  static void* GetTPtrListClassNamePointer();
};

ASSERT_SIZE(TPtrList, 0x18);
