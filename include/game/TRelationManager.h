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
  virtual void dummy11() = 0;
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
  virtual void dummy29() = 0;
  virtual void dummy30() = 0;
  virtual void dummy31() = 0;
  virtual void Refresh80() = 0; // slot 80

  unsigned char pad04[0xB6 - 4];
  // 0xB6..0xE4; fieldB6[0x15]/[0x16] occupy 0xE0/0xE2 (relationNeedSlotE0/E2).
  short fieldB6[0x17];
};
