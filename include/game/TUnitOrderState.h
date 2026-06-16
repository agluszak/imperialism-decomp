#pragma once

#include "game/TObject.h"

// Base class for the per-nation pending unit-order objects (civilian work,
// military recruit, navy task-force). The concrete subclasses each install their
// own vtable in the packed 0x0066ee18 region:
//   TUnitOrderState     -> 0x0066ee18 (this base, 18-slot table; 0x0e-0x11 null)
//   TCivWorkOrderState  -> 0x0066ee60
//   military recruit    -> 0x0066eea8
// VTABLE: IMPERIALISM 0x0066ee18
class TUnitOrderState : public TObject {
public:
  // --- TObject overrides ---
  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00
  ~TUnitOrderState() override; // slot 0x04

  // slot 0x08 Serialize is inherited from TObject unchanged (0x485e90)

  void WriteTo(TStream* stream) override; // slot 0x14
  void ReadFrom(TStream* stream) override; // slot 0x18
  void Free() override; // slot 0x1c

  // slot 0x20 ShallowClone is inherited unchanged (0x4798d0)
  // slot 0x24 ShallowFree is inherited unchanged (0x415ce0)

  // --- TUnitOrderState virtual functions ---
  virtual void VTableSlot10(int pOwnerContext); // slot 0x28
  virtual void DispatchSlot2C(); // slot 0x2c
  virtual void DetachUnitOrderFromOwnerAndReset(); // slot 0x30
  virtual void SetOrderModeSlot34(int mode, int payload); // slot 0x34

  short orderType;        // 0x04
  short field_6;          // 0x06 (init 0xffff)
  int field_8;            // 0x08
  short field_C;          // 0x0c
  short field_E;          // 0x0e
  int field_10;           // 0x10
  int field_14;           // 0x14
  short field_18;         // 0x18
  short field_1A;         // 0x1a
  unsigned char field_1C; // 0x1c
  unsigned char pad1d[3]; // 0x1d
  int field_20;           // 0x20

  // Inlined base initializer (the 0x5c28c0 / 0x5c2df0 ctors open-code this). Kept
  // header-inline so MSVC folds it into each subclass ctor and dead-store-
  // eliminates the base vptr write, leaving the single derived vptr write the
  // originals emit.
  TUnitOrderState() {
    field_10 = 0;
    field_14 = 0;
    field_6 = static_cast<short>(0xffff);
    field_8 = 0;
    field_1C = 0;
  }

  void RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                         short nOrderOwnerNationId, short arg3);
};
