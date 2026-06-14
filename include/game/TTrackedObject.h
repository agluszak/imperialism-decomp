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
  // slot 0x40 — per-turn refresh (0x004eae70 sweeps the mission queue with it).
  virtual void RefreshSlot40() = 0;
  // slot 0x44 — defense minister mission-queue sweep (0x004ec4c0).
  virtual void MissionSlot44() = 0;
  // slot 0x48 — replacement mission; returning anything other than `this` makes the
  // pruner (0x004eb0d0) swap the entry out of the queue.
  virtual TTrackedObject* GetReplacementSlot48() = 0;
  // slot 0x4C — mission-key match (kind 3 + region id, 0x004ea1c0).
  virtual char MatchesMissionKeySlot4C(int kind, int key, int mode) = 0;
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
  // slot 0x80 — adopt an unassigned military unit (0x004eae70).
  virtual void AdoptUnitSlot80(void* unit, int flag) = 0;
};
