// TScatteredShipsMission implementations.

#include "game/TScatteredShipsMission.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TScatteredShipsMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053ba60
// TScatteredShipsMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053bb20
// TScatteredShipsMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005356a0
// TScatteredShipsMission::`scalar deleting destructor'

TScatteredShipsMission::TScatteredShipsMission() : TNavyMission() {}

TScatteredShipsMission::TScatteredShipsMission(TZone* targetZone) : TNavyMission(targetZone) {}

// FUNCTION: IMPERIALISM 0x00535640
char TScatteredShipsMission::ReturnFalseSlot64() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00535660
char TScatteredShipsMission::ReturnFalseSlot60() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00535680
char TScatteredShipsMission::ReturnFalseSlot28() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053bb90
void TScatteredShipsMission::Call30() {
  marker11 = 0;
  *reinterpret_cast<float*>(&value0c) = *reinterpret_cast<const float*>(0x0065a9c8);
}

// FUNCTION: IMPERIALISM 0x0053bbb0
void TScatteredShipsMission::RefreshSlot40() {
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
}

// FUNCTION: IMPERIALISM 0x0053bbe0
TMission* TScatteredShipsMission::GetReplacementSlot48() {
  return this;
}

// FUNCTION: IMPERIALISM 0x0053bc00
void TScatteredShipsMission::SetStateByte8To2() {
  state08 = 3;
}

// FUNCTION: IMPERIALISM 0x0053bc20
void TScatteredShipsMission::ResetValue0CToZero() {
  *reinterpret_cast<float*>(&value0c) = *reinterpret_cast<const float*>(0x0065a9c8);
}

// Spreads the fixed g_Populate_Beachhead_Mission_LookupTable_00697958 percentages across
// resourceWeights2c[4], scaled by (1 + this mission's nation's navy-pressure field at +0xb6c,
// region not otherwise recovered yet). AssertValid()s the nation first (same CObject virtual
// slot 0xc dispatch used elsewhere in this file family).
// FUNCTION: IMPERIALISM 0x0053bc40
void TScatteredShipsMission::NoOpSlot3C() {
  TGreatPower* nation = g_apNationStates[nationId04];
  nation->AssertValid();
  float navyPressure = *reinterpret_cast<float*>(reinterpret_cast<char*>(nation) + 0xb6c);
  float scale = (navyPressure + 1.0f) * 0.01f;

  const unsigned short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = static_cast<float>(static_cast<short>(lookupTable[i])) * scale;
  }
}

// FUNCTION: IMPERIALISM 0x0053bcc0
char TScatteredShipsMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)key;
  (void)mode;
  return kind == 5;
}

// FUNCTION: IMPERIALISM 0x0053bdd0
void TScatteredShipsMission::MissionSlot44() {
  // TODO: promote the rest of the body (bd 1uj.16.4) -- 339 bytes, several unresolved
  // sub-calls (g_pSimMgr vtable slot 0x1c for a random roll mod 50, TZone::field_0x18
  // ring-list traversal via g_pMapActionContextListHead, ApplyJoinEmpireModeForTargetNation
  // + 0x40408e eligibility gate matching NoOpSlot9C's pattern elsewhere in this family, then
  // a childOrderList scan/promotion whose exact receiver for the two func_0x0040954d calls
  // is unclear -- one result is discarded, one stored, suggesting a hidden-arg mismatch).
  // Left as a documented TODO pending dedicated follow-up rather than guessing.
  if (orderList24 != nullptr) {
    orderList24->active_flag = 0;
    orderList24->next->SetChainActiveFlag(0);
  }
}

// FUNCTION: IMPERIALISM 0x0053bf90
TZone* TScatteredShipsMission::RefreshMissionPortZoneContextForNation() {
  return nullptr;
}
