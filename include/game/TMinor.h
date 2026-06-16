#pragma once

#include "game/TCountry.h"

// Minor-power nation row (g_apTerrainTypeDescriptorTable[7..], g_apSecondaryNationStateSlots).
// Inherits the TCountry prefix (0x94) and extends with minor-only tail state to 0x2cc.
// VTABLE: IMPERIALISM 0x00653c90
class TMinor : public TCountry {
public:
  TMinor();

  static void* CreateTMinorInstance();
  static void* GetTMinorClassNamePointer();
  static void* thunk_GetTMinorClassNamePointer_At00406ee7(void);

  CRuntimeClass* GetRuntimeClass() const override;

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  void SetDiplomacyStandingSlot48(int targetNation, int standing);
  char HasMinorStandingLinkSlot5C(int sourceNation);
  void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode);
  char HasStandingPropagationBridgeSlot90(int targetNation);
  void NotifyActionSlot94(int sourceNation, int actionCode) override;
  void NotifyNationAuxRuntimeFinalizeSlotC0(void);
  void ClearNationAuxRuntimeGrantSlotC4(int grantValue);

private:
  unsigned char minorObjectTail[0x2cc - 0x94];

protected:
  ~TMinor() {}
};

ASSERT_SIZE(TMinor, 0x2cc);
