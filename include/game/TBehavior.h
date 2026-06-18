#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"

// VTABLE: IMPERIALISM 0x00648d60
class TBehavior : public TObject {
public:
  TBehavior();

  CRuntimeClass* GetRuntimeClass() const override;
  virtual void SetDword08(undefined4 value);
  virtual unsigned char GetFlag0C();
  virtual void SetFlag0C(unsigned char value);
  virtual void NoOpSlot34(undefined4 value);

  undefined4 field_0x4;
  undefined4 field_0x8;
  unsigned char field_0xc;
  unsigned char padding_0xd[3];
};

ASSERT_SIZE(TBehavior, 0x10);
