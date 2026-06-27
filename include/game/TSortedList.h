#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TStream;

// TObject-derived linked-list base (vtable 0x00648ee0).
// Base recovered from CRuntimeClass descriptor: TSortedList -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00648ee0
class TSortedList : public TObject {
public:
  DECLARE_DYNCREATE(TSortedList)

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  int GetIntByOrdinalSlot24(int ordinal);

  virtual POSITION AddHeadSlot28(void* item);
  virtual POSITION AddHeadSlot2C(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTailSlot30(void* item);
  virtual POSITION AddTailSlot34(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTailSlot38(void* item = 0);
  virtual void* RemoveTailSlot3C();
  virtual POSITION AddTailSlot40(void* item = 0);
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

  CPtrList listState; // +0x04

  void ConstructTSortedListBaseState(int blockSize);

  TSortedList();
  static TSortedList* CreateTSortedListInstance();
};

ASSERT_SIZE(TSortedList, 0x20);
