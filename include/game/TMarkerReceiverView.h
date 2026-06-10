#pragma once

// Receiver passed to town-marker attach paths (vtable slot 0x44 adopts the marker).
class TMarkerReceiverView {
public:
  virtual void r00() = 0;
  virtual void r01() = 0;
  virtual void r02() = 0;
  virtual void r03() = 0;
  virtual void r04() = 0;
  virtual void r05() = 0;
  virtual void r06() = 0;
  virtual void r07() = 0;
  virtual void r08() = 0;
  virtual void r09() = 0;
  virtual void r10() = 0;
  virtual void r11() = 0;
  virtual void r12() = 0;
  virtual void r13() = 0;
  virtual void r14() = 0;
  virtual void r15() = 0;
  virtual void r16() = 0;
  virtual void AdoptMarkerSlot44(void* marker) = 0;
};
