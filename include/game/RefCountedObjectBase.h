#pragma once

#include "decomp_types.h"

// Game object root used by the TPtrList/TList wrapper family. This is distinct
// from MFC CObject: list wrappers store this vfptr at +0 and embed the MFC
// CPtrList engine at +4.
// VTABLE: IMPERIALISM 0x006485c0
struct RefCountedObjectBase {
  virtual ~RefCountedObjectBase() {}
  virtual void VMethod01() {}
  virtual void VMethod02() {}
  virtual void VMethod03() {}
  virtual void VMethod04() {}
  virtual void VMethod05() {}
  virtual void VMethod06() {}
  virtual void VMethod07() {}
  virtual void VMethod08() {}
  virtual void VMethod09() {}

  RefCountedObjectBase() {}
};
