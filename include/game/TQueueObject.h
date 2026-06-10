#pragma once

#include "decomp_types.h"

// VTABLE: Provisional queue object
class TQueueObject {
public:
  virtual void dummy0() = 0;
  virtual void dummy1() = 0;
  virtual void dummy2() = 0;
  virtual void dummy3() = 0;
  virtual void dummy4() = 0;
  virtual void ApplyMessageSlot14(void* message) = 0; // slot 14
  virtual void Call18() = 0;                          // slot 18
  virtual void Release1C() = 0;                       // slot 1C
  virtual void Call20() = 0; // slot 20 (TCity slot 0x14 tail-calls it, 0x004b46c0)
  virtual void Call24() = 0; // slot 24 (destructor)
  virtual void dummy10() = 0;
  virtual void* GetEntryAt1BasedSlot2C(int index) = 0; // slot 2C
  virtual void dummy12() = 0;
  virtual void dummy13() = 0;
  virtual void WritePackedIntSlot38(int* packedValue) = 0; // slot 38
  virtual void dummy15() = 0;                              // 3c
  virtual void dummy16() = 0;                              // 40
  virtual void PushPairSlot40(void* pair) = 0;             // slot 40 overload
  virtual void dummy17() = 0;                              // 44
  virtual void RefreshSlot48() = 0;                        // slot 48
  virtual int ReadIndexSlot4C(int mode, int index) = 0;    // slot 4C

  unsigned char pad04[8 - 4];
  int entryCount; // +8
};
