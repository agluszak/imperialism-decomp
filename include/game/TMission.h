#pragma once

// Mac: TMission — base mission class (hierarchy recovery in progress).
class TMission {
public:
  // Factory (0x5350d0). TEMP: forwards to stub until mission ctors use real inheritance.
  static void* CreateByKindAndNodeContext(int sourceNation, int missionKind, int arg2, int arg3,
                                          int arg4);
};

// Mission-node queue element: slot 0x28 dispatch hook (0x004daa80).
class TMissionNodeCallback {
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
  virtual void DispatchSlot28() = 0;
protected:
  ~TMissionNodeCallback() {}
};
