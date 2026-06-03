#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/RefCountedObjectBase.h"
#include "game/CPtrList.h"

struct TPtrList : public RefCountedObjectBase {
  CPtrList listState;

  static void* GetTPtrListClassNamePointer();
  void ConstructTPtrListBaseState(int ownerContext);
  void* DestructTPtrListAndMaybeFree(byte freeSelfFlag, int unused1, int unused2);
};

ASSERT_SIZE(TPtrList, 0x20);
