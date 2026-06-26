#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TApplication.h"

// Ambit-specific application subclass (size 0x54, base TApplication = 0x48).
// Introduces virtual overrides for runtime serialization and modal auto-scroll.
class TAmbitApplication : public TApplication {
public:
  TAmbitApplication();
  virtual ~TAmbitApplication() override;

  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00, 0x0049deb0
  virtual void WriteTo(TStream* stream) override;           // slot 0x05, 0x0049e2f0
  virtual void ReadFrom(TStream* stream) override;          // slot 0x06, 0x0049e280
  virtual void Free() override;                             // slot 0x07, 0x0049e1a0

  virtual void VTableSlot2B(int arg1, int arg2, int arg3) override;   // slot 0x2b, 0x0049e320
  virtual void VTableSlot2C() override;                     // slot 0x2c, 0x00414770
  virtual void VTableSlot2D(void* param_1) override;        // slot 0x2d, 0x0049e4e0

  int field_48; // 0x48
  int field_4c; // 0x4c
  int field_50; // 0x50
};
