#pragma once

#include "decomp_types.h"

undefined4 thunk_InitializeTForeignMinisterStateAndCounters(void);
undefined4 thunk_InitializeCityInteriorMinister(void);
undefined4 thunk_InitializeTMinisterBaseOrderArrayMetrics(void);
undefined4 thunk_ConstructTForeignMinister(void);
undefined4 thunk_WrapperFor_thunk_ConstructTMinister_At004be840(void);
undefined4 thunk_ConstructTDefenseMinisterBaseState(void);

// VTABLE: IMPERIALISM 0x00659c00
class TMinister {
public:
  TMinister();

  virtual void dummy0() {}
  virtual void dummy1() {}
  virtual void dummy2() {}
  virtual void dummy3() {}
  virtual void dummy4() {}
  virtual void dummy5() {}
  virtual void Call18(int arg1 = 0) { (void)arg1; } // slot 18
  virtual void Call1C() {}                          // slot 1C
  virtual void dummy8() {}
  virtual void dummy9() {}
  virtual void dummy10() {}
  virtual void dummy11() {}
  virtual void dummy12() {}
  virtual void dummy13() {}
  virtual void dummy14() {}
  virtual void dummy15() {}
  virtual void dummy16() {}
  // slot 0x44 — handed the marker receiver after Frog City creation (0x004dfae0).
  virtual void NotifySlot44(void* receiver) { (void)receiver; }
  virtual void dummy18() {}
  virtual void Call4C() {}
  virtual void dummy20() {}
  virtual void Call54() {} // slot 0x54 (TAutoGreatPower 0x004e7590 tail-calls it)
  virtual void Call58() {} // slot 0x58 (TAutoGreatPower 0x004e7af0 tail-calls it)
  virtual void dummy23() {}
  virtual void dummy24() {}
  virtual void dummy25() {}
  virtual void dummy26() {}
  virtual void dummy27() {}
  virtual void dummy28() {}
  virtual void dummy29() {}
  virtual void dummy30() {}
  virtual void dummy31() {}
  virtual void Call80() {} // slot 80 (TGreatPower slot 0x78 body 0x004de7e0 forwards here)
  virtual void dummy33() {}
  virtual void dummy34() {}
  virtual void Call8C() {} // slot 8C
  virtual void Call90() {}
  virtual void Call94() {}
  // slot 0x98 — foreign-minister proposal dispatch (TAutoGreatPower 0x004e79d0).
  virtual void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)targetNation;
  }
  // slot 0x9c — order-state recompute fired before the collapse production reset
  // (TAutoGreatPower::ClearDiplomacyState1c6Block override 0x004e7a50 calls it on the
  // foreign minister).
  virtual void RecomputeOrderStateSlot9C() {}
  virtual void dummy40() {}
  virtual void dummy41() {}
  virtual void dummy42() {}
  virtual void dummy43() {}
  virtual void dummy44() {}
  virtual void dummy45() {}
  virtual void dummy46() {}
  virtual void dummy47() {}
  // slot 0xc0 — home city/region record index (interior minister; 0x004dfae0).
  virtual int GetHomeCityRecordIndexSlotC0() { return 0; }
  virtual void dummy49() {}
  virtual void dummy50() {}
  virtual void dummy51() {}
  virtual void dummy52() {}
  virtual void CallD4() {}

  unsigned char pad04[0xC - 4];
  short skillIndexC; // +0xC
  unsigned char pad0e[0x24 - 0x0E];
  // +0x24/+0x26/+0x28 — capability flags gating categories 3/4/5 in TGreatPower
  // slot 0x40 (body 0x004dcaa0).
  short capabilityFlag24;
  short capabilityFlag26;
  short capabilityFlag28;
};
