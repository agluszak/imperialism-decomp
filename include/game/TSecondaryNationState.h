#pragma once

#include "decomp_types.h"
#include "game/CString.h"

#define TSECONDARYNATIONSTATE_VTABLE_SLOT(n) virtual void SecondaryNationStateDummy##n(void) = 0

// VTABLE: IMPERIALISM 0x00653c90
// Terrain / minor-nation rows in g_apTerrainTypeDescriptorTable. Vtable prefix diverges
// from TGreatPower at slot 0x00 (see tmp_decomp/class_discovery/nationstate/model_b_decision.md).
class TSecondaryNationState {
public:
  TSecondaryNationState();
  TSECONDARYNATIONSTATE_VTABLE_SLOT(00);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(01);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(02);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(03);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(04);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(05);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(06);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(07);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(08);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(09);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(10);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(11);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(12);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(13);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(14);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(15);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(16);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(17);
  virtual void SetDiplomacyStandingSlot48(int targetNation, int standing) = 0; // 0x48
  virtual void VTableSlot4C_Provisional(int arg0, int arg1) = 0;               // 0x4c
  TSECONDARYNATIONSTATE_VTABLE_SLOT(20);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(21);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(22);
  virtual char HasMinorStandingLinkSlot5C(int sourceNation) = 0; // 0x5c
  TSECONDARYNATIONSTATE_VTABLE_SLOT(24);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(25);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(26);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(27);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(28);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(29);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(30);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(31);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(32);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(33);
  TSECONDARYNATIONSTATE_VTABLE_SLOT(34);
  virtual void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation,
                                                       int packedRelationCode) = 0; // 0x8c
  virtual char HasStandingPropagationBridgeSlot90(int targetNation) = 0;            // 0x90
  virtual void NotifyActionSlot94(int sourceNation, int actionCode) = 0;            // 0x94

  CString identitySharedString0;
  CString identitySharedString1;
  unsigned char pad0c[0x0e - 0x0c];
  short ownerNationSlot0e; // 0x0e — terrain owner; -1 unowned
};

#undef TSECONDARYNATIONSTATE_VTABLE_SLOT
