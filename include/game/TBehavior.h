#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"

// VTABLE: IMPERIALISM 0x00648d60
class TBehavior : public TObject {
public:
// === BEGIN GENERATED DECLS (TBehavior) — refreshed by recover-class; do not hand-edit ===
  virtual ~TBehavior(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slots 0x0a-0x0d (bytes 0x28-0x34) are the typed virtuals declared below
  // (SetDword08/GetFlag0C/SetFlag0C/NoOpSlot34); the generated Orphan*
  // placeholders were duplicates of these slots and were removed.
// === END GENERATED DECLS (TBehavior) ===
  TBehavior();

  DECLARE_DYNCREATE(TBehavior)
  virtual void SetDword08(undefined4 value);     // slot 0x0a byte 0x28 0x487280
  virtual unsigned char GetFlag0C();             // slot 0x0b byte 0x2c 0x4872a0
  virtual void SetFlag0C(unsigned char value);   // slot 0x0c byte 0x30 0x4872c0
  virtual void NoOpSlot34(undefined4 value);     // slot 0x0d byte 0x34 0x4872e0

  undefined4 field_0x4;
  undefined4 field_0x8;
  unsigned char field_0xc;
  unsigned char padding_0xd[3];
};

ASSERT_SIZE(TBehavior, 0x10);

