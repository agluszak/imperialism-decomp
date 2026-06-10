#pragma once

class TRelationManager {
public:
  virtual void dummy0() = 0;
  virtual void dummy1() = 0;
  virtual void dummy2() = 0;
  virtual void dummy3() = 0;
  virtual void dummy4() = 0;
  virtual void dummy5() = 0;
  virtual void Call18(int arg1 = 0) = 0; // slot 18
  virtual void Call1C() = 0;             // slot 1C
  virtual void dummy8() = 0;
  virtual void dummy9() = 0;
  virtual void Call28() = 0; // slot 28
  virtual void Call2C() = 0; // slot 2C (TGreatPower slot 0x37 body 0x004dca60 forwards here)
  virtual void RefreshOrderStateSlot0C() = 0; // slot 0x0c (offset 0x30)
  virtual void dummy13() = 0;
  virtual void dummy14() = 0;
  virtual void dummy15() = 0;
  virtual void dummy16() = 0;
  virtual void Call44() = 0; // slot 44
  virtual void dummy18() = 0;
  virtual void dummy19() = 0;
  virtual void dummy20() = 0;
  virtual void dummy21() = 0;
  virtual void dummy22() = 0;
  virtual void dummy23() = 0;
  virtual void dummy24() = 0;
  virtual void dummy25() = 0;
  virtual void dummy26() = 0;
  virtual void dummy27() = 0;
  virtual void dummy28() = 0;
  // slot 0x74 — returns the city production-summary record (shorts at +0x22/+0x24/
  // +0x28 summed by TGreatPower slot 0x65, body 0x004dd7f0).
  virtual void* GetCitySummaryRecordSlot74() = 0;
  virtual void dummy30() = 0;
  virtual void dummy31() = 0;
  virtual void Refresh80() = 0; // slot 80

  unsigned char pad04[0xAC - 4];
  class TGreatPower* ownerNationAc; // 0xAC — owning nation state (0x004b4dc0)
  unsigned char pad_b0[0xB6 - 0xB0];
  // 0xB6..0xE4; fieldB6[0x15]/[0x16] occupy 0xE0/0xE2 (relationNeedSlotE0/E2).
  short fieldB6[0x17];
  unsigned char pad_e4[0x1DC - 0xE4];
  // 0x1DC — 23-entry per-city production order table (0x004b4dc0).
  short productionOrderTable1dc[0x17];

  int GetBuildingProductionValueBySlot(short buildingSlot);
};
