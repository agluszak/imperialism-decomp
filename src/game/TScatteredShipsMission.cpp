// TScatteredShipsMission implementations.

#include "game/TScatteredShipsMission.h"
#include "game/TStream.h"
#include "game/TZone.h"

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

// Generic child-link-chain flag setter shared across navy mission classes
// (misattributed class prefix in Ghidra; see header).
// FUNCTION: IMPERIALISM 0x00536f70
void TScatteredShipsMission::SetMapOrderEntryChildFlags(TMapOrderChildLinkNode* node,
                                                        unsigned char flag) {
  for (; node != nullptr; node = node->next) {
    node->active_flag = flag;
  }
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

// FUNCTION: IMPERIALISM 0x0053bc40
void TScatteredShipsMission::NoOpSlot3C() {
  // TODO: PopulateScatteredShipsMissionResourceWeightsFromNationNavyPressure --
  // pending recovery of the per-nation navy-pressure field and weight table.
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
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
  // TODO: SelectMapActionContextAndPromoteMissionOrderChain -- pending
  // recovery of the map-action-context selection and order-chain promotion.
  if (orderList24 != nullptr) {
    orderList24->active_flag = 0;
    SetMapOrderEntryChildFlags(orderList24->next, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0053bf90
TZone* TScatteredShipsMission::RefreshMissionPortZoneContextForNation() {
  return nullptr;
}
