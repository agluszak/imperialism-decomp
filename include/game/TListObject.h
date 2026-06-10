#pragma once

// Virtual call view for the game TList/TSortedList family. This is not a third
// allocation hierarchy: concrete objects use the TPtrList state layout
// (RefCountedObjectBase vfptr + embedded CPtrList at +4) and install a concrete
// TList-like vtable such as 0x00648f78 or 0x00648ee0.
//
// Declaration index N emits vtable offset 4*N; every name below matches its
// emitted offset (verified against concrete vtable 0x00648f78). Do not insert
// overload decls — they silently shift every later slot (heuristics note 98).
class TListObject {
public:
  virtual void GetClassDescDynamicSlot00_Provisional() = 0;
  virtual void DeleteSelfSlot04_Provisional(int freeFlag) = 0;
  virtual void DispatchSlot08_Provisional() = 0;
  virtual void NoOpSlot0C_Provisional() = 0;
  virtual void NoOpSlot10_Provisional() = 0;
  virtual void ResetSlot14() = 0;
  virtual void Call18(int arg1 = 0) = 0;
  virtual void Release1C() = 0;
  virtual void VTableSlot20_Provisional() = 0;
  virtual int GetIntByOrdinalSlot24(int ordinal) = 0;
  // Slot 0x28. Region lists return their entry count here (0x004dbf00 and 0x00517c30
  // both consume EAX as a count); other call sites use it as a release hook and
  // ignore the return value.
  virtual int GetCountOrReleaseSlot28() = 0;
  virtual void* GetNodeByOrdinalSlot2C(int mode, int ordinal) = 0;
  virtual void AddTail30(void* item) = 0;
  // Slot 0x34: remove a value entry (0x004e2270 passes the region id).
  virtual void RemoveIntSlot34(int value) = 0;
  virtual void Call38() = 0;
  virtual void VTableSlot3C_Provisional() = 0;
  virtual void VTableSlot40_Provisional() = 0;
  virtual void VTableSlot44_Provisional() = 0;
  // Slot 0x48: CPtrList entry count (concrete body 0x004886d0 returns this+0x10).
  virtual int GetCountSlot48() = 0;
  // Slot 0x4c: 1-based get-by-ordinal (concrete body 0x004886f0, FindIndex->data).
  virtual void* GetTrackedEntrySlot4C(int ordinal = 0) = 0;
  // Slot 0x50: remove the entry at 1-based ordinal (0x004e7230 pops entries with it).
  virtual void RemoveEntryAtSlot50(int ordinal) = 0;
  // Slot 0x54: pop-and-release every entry (concrete body 0x00488750).
  virtual void Call54() = 0;
  // Slot 0x58: Call54 then Release1C on self (concrete body 0x004887b0).
  virtual void Call58() = 0;
  virtual void VTableSlot5C_Provisional() = 0;
  // Slot 0x60: store *entryPtr as the data of the node at 1-based ordinal (concrete
  // body 0x00488840: FindIndex(ordinal-1)->data = *entryPtr; third arg unused).
  virtual void SetEntryDataAtSlot60(int ordinal, void** entryPtr, int unusedFlag) = 0;
};
