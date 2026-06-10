#pragma once

#include "decomp_types.h"

undefined4 thunk_InitializeTForeignMinisterStateAndCounters(void);
undefined4 thunk_InitializeCityInteriorMinister(void);
undefined4 thunk_InitializeTMinisterBaseOrderArrayMetrics(void);
undefined4 thunk_ConstructTForeignMinister(void);
undefined4 thunk_WrapperFor_thunk_ConstructTMinister_At004be840(void);
undefined4 thunk_ConstructTDefenseMinisterBaseState(void);

class TMinister {
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
  virtual void dummy10() = 0;
  virtual void dummy11() = 0;
  virtual void dummy12() = 0;
  virtual void dummy13() = 0;
  virtual void dummy14() = 0;
  virtual void dummy15() = 0;
  virtual void dummy16() = 0;
  // slot 0x44 — handed the marker receiver after Frog City creation (0x004dfae0).
  virtual void NotifySlot44(void* receiver) = 0;
  virtual void dummy18() = 0;
  virtual void Call4C() = 0;
  virtual void dummy20() = 0;
  virtual void Call54() = 0; // slot 0x54 (TAutoGreatPower 0x004e7590 tail-calls it)
  virtual void Call58() = 0; // slot 0x58 (TAutoGreatPower 0x004e7af0 tail-calls it)
  virtual void dummy23() = 0;
  virtual void dummy24() = 0;
  virtual void dummy25() = 0;
  virtual void dummy26() = 0;
  virtual void dummy27() = 0;
  virtual void dummy28() = 0;
  virtual void dummy29() = 0;
  virtual void dummy30() = 0;
  virtual void dummy31() = 0;
  virtual void Call80() = 0; // slot 80 (TGreatPower slot 0x78 body 0x004de7e0 forwards here)
  virtual void dummy33() = 0;
  virtual void dummy34() = 0;
  virtual void Call8C() = 0; // slot 8C
  virtual void Call90() = 0;
  virtual void Call94() = 0;
  // slot 0x98 — foreign-minister proposal dispatch (TAutoGreatPower 0x004e79d0).
  virtual void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) = 0;
  // slot 0x9c — order-state recompute fired before the collapse production reset
  // (TAutoGreatPower::ClearDiplomacyState1c6Block override 0x004e7a50 calls it on the
  // foreign minister).
  virtual void RecomputeOrderStateSlot9C() = 0;
  virtual void dummy40() = 0;
  virtual void dummy41() = 0;
  virtual void dummy42() = 0;
  virtual void dummy43() = 0;
  virtual void dummy44() = 0;
  virtual void dummy45() = 0;
  virtual void dummy46() = 0;
  virtual void dummy47() = 0;
  // slot 0xc0 — home city/region record index (interior minister; 0x004dfae0).
  virtual int GetHomeCityRecordIndexSlotC0() = 0;
  virtual void dummy49() = 0;
  virtual void dummy50() = 0;
  virtual void dummy51() = 0;
  virtual void dummy52() = 0;
  virtual void CallD4() = 0;

  unsigned char pad04[0xC - 4];
  short skillIndexC; // +0xC
  unsigned char pad0e[0x24 - 0x0E];
  // +0x24/+0x26/+0x28 — capability flags gating categories 3/4/5 in TGreatPower
  // slot 0x40 (body 0x004dcaa0).
  short capabilityFlag24;
  short capabilityFlag26;
  short capabilityFlag28;
};
