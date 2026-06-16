#pragma once

// Base class for the per-nation pending unit-order objects (civilian work,
// military recruit, navy task-force). The concrete subclasses each install their
// own vtable in the packed 0x0066ee18 region:
//   TUnitOrderState     -> 0x0066ee18 (this base, 18-slot table; 0x0e-0x11 null)
//   TCivWorkOrderState  -> 0x0066ee60
//   military recruit    -> 0x0066eea8
// The slot functions (Serialize/Deserialize/turn-event handlers) live at fixed
// addresses owned elsewhere; until each is migrated onto this class as a real
// virtual, the base slot bodies are temporary structural placeholders (heuristic
// 44). They exist only to give the subclasses a concrete, instantiable base so
// the constructors emit a real compiler vptr write that reccmp pairs to the
// `// VTABLE:` address.
// VTABLE: IMPERIALISM 0x0066ee18
class TUnitOrderState {
public:
  virtual void s00() {}
  virtual void s01() {}
  virtual void s02() {}
  virtual void s03() {}
  virtual void s04() {}
  // Slots 0x14/0x18 — stream serialization pair: TGreatPower 0x004da500 writes each
  // tracked order via [vt+0x14](stream); 0x004da3e0 reads each via [vt+0x18](stream).
  virtual void WriteToStreamSlot14(void* stream) {
    (void)stream;
  }
  virtual void ReadFromStreamSlot18(void* stream) {
    (void)stream;
  }
  virtual void s07() {}
  virtual void s08() {}
  virtual void s09() {}
  virtual void VTableSlot10(int pOwnerContext) {
    (void)pOwnerContext;
  } // slot 10 at 0x28
  // Slot 0x2c — per-order dispatch hook invoked by TGreatPower slot 0x4c (0x004e0220).
  virtual void DispatchSlot2C() {}
  virtual void VTableSlot30_Provisional() {}
  // Slot 0x34 — TGreatPower slot 0x0d (0x004d7770) calls this on a fresh military
  // recruit order with (2, -1).
  virtual void SetOrderModeSlot34(int mode, int payload) {
    (void)mode;
    (void)payload;
  }

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

protected:
  ~TUnitOrderState() {}
};
