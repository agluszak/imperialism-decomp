#pragma once

// Virtual call view for the game TList/TSortedList family. This is not a third
// allocation hierarchy: concrete objects use the TPtrList state layout
// (RefCountedObjectBase vfptr + embedded CPtrList at +4) and install a concrete
// TList-like vtable such as 0x00648f78 or 0x00648ee0.
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
  virtual int GetCountSlot28() = 0; // NOTE: emits offset 0x2c (decl index 11)
  virtual void* GetNodeByOrdinalSlot2C(int mode, int ordinal) = 0;
  virtual void* GetEntrySlot2C(int index) = 0; // slot 2C overload
  virtual void AddTail30(void* item) = 0;
  virtual void VTableSlot34_Provisional() = 0;
  virtual void Call38() = 0;
  virtual void AddEntrySlot38(void* entry) = 0; // slot 38 overload
  virtual void VTableSlot3C_Provisional() = 0;
  virtual void VTableSlot40_Provisional() = 0;
  virtual void VTableSlot44_Provisional() = 0;
  virtual int GetCountSlot48() = 0;
  virtual void* GetTrackedEntrySlot4C(int ordinal = 0) = 0;
  virtual void TPtrListSlot50_Provisional() = 0;
  virtual void Call54() = 0;
  virtual void Call58() = 0;
};
