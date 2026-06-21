#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TStream;

// Common state for the game list wrappers. Concrete leaves such as TList and
// TSortedList install their own vtables, but this remains a real polymorphic
// class because it owns storage and concrete virtual bodies.
//
// Slots 0x28..0x60 are the list-engine dispatch surface (TList vtable 0x648f78).
struct TPtrList : public TObject {
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

  // Base list-engine virtuals shared by all leaves (TList/TSortedList vtables
  // 0x648f78/0x648ee0, in-construction base vtable 0x6485c0). Bodies return 0;
  // derived leaves (e.g. TArmyStackList) override VirtualSlot6C.
  virtual int VirtualSlot64();  // byte 0x64 (0x487d90)
  virtual int VirtualSlot68();  // byte 0x68 (0x487dd0)
  virtual int VirtualSlot6C();  // byte 0x6c (0x487b30)
  virtual int VirtualSlot70();  // byte 0x70 (0x487b60)
  virtual int VirtualSlot74();  // byte 0x74 (0x487bd0)
  virtual int VirtualSlot78();  // byte 0x78 (0x487cc0)

  CPtrList listState;

  static void* GetTPtrListClassNamePointer();
  void ConstructTPtrListBaseState(int ownerContext);
};

ASSERT_SIZE(TPtrList, 0x20);
