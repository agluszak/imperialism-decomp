#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"
#include "game/mfc.h"

class TStream;

// CPtrArray-derived linked-list wrapper (vtable TBD).
// Base recovered from CRuntimeClass descriptor: TPtrList -> TSortedPtrList -> CPtrArray -> CObject.
class TPtrList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TPtrList)

  // Overrides of TSortedPtrList slots (0x28-0x40):
  virtual POSITION AddHeadSlot28(void* item);
  virtual POSITION AddHeadSlot2C(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTailSlot30(void* item);
  virtual POSITION AddTailSlot34(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTailSlot38(void* item = 0);
  virtual void* RemoveTailSlot3C();
  virtual POSITION AddTailSlot40(void* item = 0);
  // New slots (0x44-0x78):
  virtual void* RemoveHeadSlot44();
  virtual int GetCountSlot48();
  virtual void* GetEntryByOrdinalSlot4C(int ordinal = 0);
  virtual void RemoveAtOrdinalSlot50(int ordinal);
  virtual void FreePayloadsSlot54();
  virtual void FreePayloadsAndDestroySlot58();
  virtual void RemoveAllSlot5C();
  virtual void SetAtOrdinalSlot60(int ordinal, void** entryPtr, int unusedFlag);
  virtual int VirtualSlot64();
  virtual int VirtualSlot68();
  virtual int VirtualSlot6C();
  virtual int VirtualSlot70();
  virtual int VirtualSlot74();
  virtual int VirtualSlot78();

  int GetIntByOrdinalSlot24(int ordinal);

  static void* GetTPtrListClassNamePointer();
};

ASSERT_SIZE(TPtrList, 0x18);
