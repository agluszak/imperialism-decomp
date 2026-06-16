#pragma once

#include "decomp_types.h"

// Game object root used by the TPtrList/TList wrapper family. This is distinct
// from MFC CObject: list wrappers store this vfptr at +0 and embed the MFC
// CPtrList engine at +4.
//
// DUAL ROLE WARNING: vtable 0x006485c0 is also written transiently during EH
// construction of unrelated CString-bearing classes (TZone, TAdmiral, TGreatPower,
// TControl, TSimMgr, …). Those writes are MSVC partial-construction sentinels, NOT
// evidence of list-wrapper inheritance. Only TPtrList/TList/TSortedList/TPtrArray
// family members should use `public RefCountedObjectBase`.
//
// Virtual slots 1..9 (offsets 0x04..0x24) mirror the prefix of TList vtable
// 0x648f78. TPtrList overrides slots 5..7; TList/TSortedList override slot 1.
// VTABLE: IMPERIALISM 0x006485c0
struct RefCountedObjectBase {
  // No C++ virtual destructor: the original vtable starts at slot 0x00 with the
  // GetRuntimeClass-equivalent and frees through DeleteSelfSlot04 (the scalar
  // deleting destructor), so a leading virtual ~dtor would inject an extra slot
  // and shift every named slot by 4 (matches the TObject 10-slot prefix).
  virtual void GetClassDescDynamicSlot00() {}
  virtual void DeleteSelfSlot04(int freeFlag) {}
  virtual void DispatchSlot08() {}
  virtual void NoOpSlot0C() {}
  virtual void NoOpSlot10() {}
  virtual void ResetSlot14(void* message = 0) { (void)message; }
  virtual void Call18(int arg1 = 0) {}
  virtual void Release1C() {}
  virtual void VTableSlot20() {}
  virtual int GetIntByOrdinalSlot24(int ordinal) { return 0; }

  RefCountedObjectBase() {}
};
