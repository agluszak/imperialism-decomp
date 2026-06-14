#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/RefCountedObjectBase.h"
#include "game/CPtrList.h"

// Common state for the game list wrappers. Concrete leaves such as TList and
// TSortedList install their own vtables, but this remains a real polymorphic
// class because it owns storage and concrete virtual bodies.
//
// Slots 0x28..0x60 are the list-engine dispatch surface (TList vtable 0x648f78).
struct TPtrList : public RefCountedObjectBase {
  virtual void ResetSlot14(void* message = 0) override { (void)message; }
  virtual void Call18(int arg1 = 0) override { (void)arg1; }
  virtual void Release1C() override;

  virtual int GetCountOrReleaseSlot28();
  virtual void* GetNodeByOrdinalSlot2C(int mode, int ordinal);
  virtual void AddTail30(void* item);
  virtual void RemoveIntSlot34(int value) { (void)value; }
  virtual void Call38() {}
  virtual void VTableSlot3C_Provisional() {}
  virtual void VTableSlot40_Provisional() {}
  virtual void VTableSlot44_Provisional() {}
  virtual int GetCountSlot48();
  virtual void* GetTrackedEntrySlot4C(int ordinal = 0);
  virtual void RemoveEntryAtSlot50(int ordinal);
  virtual void Call54();
  virtual void Call58();
  virtual void VTableSlot5C_Provisional() {}
  virtual void SetEntryDataAtSlot60(int ordinal, void** entryPtr, int unusedFlag);

  CPtrList listState;

  static void* GetTPtrListClassNamePointer();
  void ConstructTPtrListBaseState(int ownerContext);
};

ASSERT_SIZE(TPtrList, 0x20);
