#pragma once

#include "decomp_types.h"
#include "game/CString.h"

#define TMINOR_VTABLE_SLOT(n)                                                                      \
  virtual void TMinorDummy##n(void) {}

// VTABLE: IMPERIALISM 0x00653c90
// Mac TMinor / Windows terrain+minor rows (g_apTerrainTypeDescriptorTable,
// g_apSecondaryNationStateSlots). RTTI: g_pClassDescTMinor @ 0x006536a0. No separate g_vtblTMinor —
// this vtable is the only one.
class TMinor {
public:
  TMinor();

  static void* CreateTMinorInstance();
  static void* GetTMinorClassNamePointer();
  static void* thunk_GetTMinorClassNamePointer_At00406ee7(void);

  virtual void* GetClassDescPointerSlot00(void);
  TMINOR_VTABLE_SLOT(01);
  TMINOR_VTABLE_SLOT(02);
  TMINOR_VTABLE_SLOT(03);
  TMINOR_VTABLE_SLOT(04);
  TMINOR_VTABLE_SLOT(05);
  TMINOR_VTABLE_SLOT(06);
  TMINOR_VTABLE_SLOT(07);
  TMINOR_VTABLE_SLOT(08);
  TMINOR_VTABLE_SLOT(09);
  TMINOR_VTABLE_SLOT(10);
  TMINOR_VTABLE_SLOT(11);
  TMINOR_VTABLE_SLOT(12);
  virtual void SetDiplomacyStandingSlot48(int targetNation, int standing) {} // 0x48
  virtual void VTableSlot4C_Provisional(int arg0, int arg1) {}               // 0x4c
  TMINOR_VTABLE_SLOT(20);
  TMINOR_VTABLE_SLOT(21);
  TMINOR_VTABLE_SLOT(22);
  virtual char HasMinorStandingLinkSlot5C(int sourceNation) {
    return 0;
  } // 0x5c
  TMINOR_VTABLE_SLOT(24);
  TMINOR_VTABLE_SLOT(25);
  TMINOR_VTABLE_SLOT(26);
  TMINOR_VTABLE_SLOT(27);
  TMINOR_VTABLE_SLOT(28);
  TMINOR_VTABLE_SLOT(29);
  TMINOR_VTABLE_SLOT(30);
  TMINOR_VTABLE_SLOT(31);
  TMINOR_VTABLE_SLOT(32);
  TMINOR_VTABLE_SLOT(33);
  TMINOR_VTABLE_SLOT(34);
  virtual void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode) {
  } // 0x8c
  virtual char HasStandingPropagationBridgeSlot90(int targetNation) {
    return 0;
  }                                                                    // 0x90
  virtual void NotifyActionSlot94(int sourceNation, int actionCode) {} // 0x94

  CString identitySharedString0;
  CString identitySharedString1;
  short fallbackNationSlot0c; // 0x0c — owner used when ownerNationSlot0e tag < 100
  short ownerNationSlot0e;    // 0x0e — terrain owner tag; -1 unowned; 100/200-biased
  unsigned char pad10[0x44 - 0x10];
  // 0x44 — military unit list (same offset/record shape as TGreatPower::militaryUnitList44;
  // summed against g_Classify_Nation_Military_LookupTable_00695CD4 in 0x004e0fe0/0x004e1300).
  class TListObject* militaryUnitList44;
  unsigned char pad48[0x90 - 0x48];
  // 0x90 — owned region id list (same offset as TGreatPower::ownedRegionList; walked by
  // the border check at 0x00517c30 via list slots 0x28/0x24).
  class TListObject* ownedRegionList90;

private:
  unsigned char minorObjectTail[0x2cc - (0x94 - 0x10)];
};

#undef TMINOR_VTABLE_SLOT
