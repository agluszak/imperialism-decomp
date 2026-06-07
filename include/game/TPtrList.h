#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/RefCountedObjectBase.h"
#include "game/CPtrList.h"

// Common state for the game list wrappers. Concrete leaves such as TList and
// TSortedList install their own vtables, but this remains a real polymorphic
// class because it owns storage and concrete virtual bodies.
struct TPtrList : public RefCountedObjectBase {
  virtual void VMethod05() {}
  virtual void VMethod06() {}
  virtual void VMethod07() {}

  CPtrList listState;

  static void* GetTPtrListClassNamePointer();
  void ConstructTPtrListBaseState(int ownerContext);
  void* DestructTPtrListAndMaybeFree(byte freeSelfFlag, int unused1, int unused2);
};

ASSERT_SIZE(TPtrList, 0x20);
