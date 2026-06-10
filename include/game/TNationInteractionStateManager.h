#pragma once
class TNationInteractionStateManager {
public:
  virtual void dummy0() = 0;
  virtual void dummy1() = 0;
  virtual void dummy2() = 0;
  virtual void dummy3() = 0;
  virtual void dummy4() = 0;
  virtual void dummy5() = 0;
  virtual void dummy6() = 0;
  virtual void dummy7() = 0;
  virtual void dummy8() = 0;
  virtual void dummy9() = 0;
  virtual void dummy10() = 0;
  virtual void dummy11() = 0;
  virtual void dummy12() = 0;
  virtual void dummy13() = 0;
  virtual void dummy14() = 0;
  // slot 0x3c — nonzero when the capability category (3/4/5) is active
  // (TGreatPower slot 0x40, body 0x004dcaa0).
  virtual short IsCapabilityCategoryActiveSlot3C(int category) = 0;
  virtual void dummy16() = 0;
  virtual void dummy17() = 0;
  virtual void dummy18() = 0;
  virtual int QueryInt4C() = 0; // slot 4C
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
  virtual void dummy32() = 0;
  // slot 0x84 — maps a proposal code into a capability category's effective code
  // (TGreatPower slot 0x40, body 0x004dcaa0).
  virtual short ResolveProposalCodeForCategorySlot84(int proposalCode, int category) = 0;
};
