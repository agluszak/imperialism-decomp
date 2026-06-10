#pragma once
class TTrackedObject {
public:
  virtual void dummy0() = 0;
  virtual void dummy1() = 0;
  virtual void dummy2() = 0;
  // slot 0x0C — detach notification (invoked while draining autoTrackedListB60, 0x004e7230).
  virtual void NotifyDetachSlot0C() = 0;
  virtual void dummy4() = 0;
  virtual void dummy5() = 0;
  virtual void dummy6() = 0;
  virtual void Release1C() = 0; // slot 1C
  virtual void dummy8() = 0;
  virtual void dummy9() = 0;
  virtual void dummy10() = 0;
  virtual void dummy11() = 0;
  virtual void Call30() = 0; // slot 30
  virtual void dummy13() = 0;
  virtual void dummy14() = 0;
  virtual void dummy15() = 0;
  virtual void dummy16() = 0;
  virtual void dummy17() = 0;
  virtual void dummy18() = 0;
  // slot 0x4C — mission-key match (kind 3 + region id, 0x004ea1c0).
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) = 0;
};
