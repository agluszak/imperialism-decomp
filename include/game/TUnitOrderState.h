#pragma once

class TUnitOrderState {
public:
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void VTableSlot10(int pOwnerContext) = 0; // slot 10 at 0x28

  short orderType;         // 0x04
  unsigned char pad06[2];  // 0x06
  int field_8;             // 0x08
  short field_C;           // 0x0c
  unsigned char pad0e[10]; // 0x0e
  short field_18;          // 0x18
  short field_1A;          // 0x1a
  unsigned char field_1C;  // 0x1c
  unsigned char pad1d[3];  // 0x1d
  int field_20;            // 0x20

  void RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                         short nOrderOwnerNationId, short arg3);
  void thunk_RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                               short nOrderOwnerNationId, short arg3);
};
