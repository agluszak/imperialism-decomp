#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"

class TEventHandler;

// VTABLE: IMPERIALISM 0x00648d60
class TBehavior : public TObject {
public:
  virtual ~TBehavior() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slots 0x0a-0x0d (bytes 0x28-0x34) are the behavior-owner contract recovered
  // from the Mac symbols and the Windows field accesses.
  TBehavior();

  DECLARE_DYNCREATE(TBehavior)
  virtual void SetOwner(TEventHandler* owner);    // slot 0x0a byte 0x28 0x487280
  virtual unsigned char IsEnabled();              // slot 0x0b byte 0x2c 0x4872a0
  virtual void SetEnabled(unsigned char enabled); // slot 0x0c byte 0x30 0x4872c0
  virtual void Draw(RECT* bounds);                // slot 0x0d byte 0x34 0x4872e0

  unsigned long behaviorTag;
  TEventHandler* owner;
  unsigned char enabled;
  unsigned char padding0d[3];
};

ASSERT_SIZE(TBehavior, 0x10);
