#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x00649068
class TPtrList : public TSortedPtrList {
public:
  // FUNCTION: IMPERIALISM 0x004884f0
  ~TPtrList() override {}
  // NOOP: verified empty in original 0x00488433
  TPtrList() {}
  DECLARE_DYNCREATE(TPtrList)

  virtual void PrependCopiedRecordToPtrList(void* record); // slot 0x48 0x488470
};

ASSERT_SIZE(TPtrList, 0x18);
