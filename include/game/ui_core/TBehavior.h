#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/app/TObject.h"

class TEventHandler;

// VTABLE: IMPERIALISM 0x00648d60
class TBehavior : public TObject {
public:
  virtual ~TBehavior() override; // slot 0x01 (scalar deleting destructor)
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
