#include "game/TNavyTacUnit.h"

#include "game/global_data_tables.h"
#include "game/TShip.h"

// FUNCTION: IMPERIALISM 0x0059ed60
TShip* TNavyTacUnit::GetSourceTaskForce() {
  return sourceTaskForce34;
}

// SYNTHETIC: IMPERIALISM 0x0059ed80
// TNavyTacUnit::`scalar deleting destructor'
TNavyTacUnit::~TNavyTacUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a6240
// TNavyTacUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a6270
// TNavyTacUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyTacUnit, TTacticalUnit)

TNavyTacUnit::TNavyTacUnit() {}

// FUNCTION: IMPERIALISM 0x005a6310
int TNavyTacUnit::GetBaseActionPoints() {
  return baseActionPoints3c;
}

// FUNCTION: IMPERIALISM 0x005a6330
int TNavyTacUnit::GetUnitRange() {
  return sourceTaskForce34->GetOrderNodeDescriptorWord0CByResourceType();
}

// FUNCTION: IMPERIALISM 0x005a6350
float TNavyTacUnit::GetBaseAttackPower() {
  return g_afTacticalNavyBaseAttackPowerByUnitType[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a6370
float TNavyTacUnit::GetDamageScale() {
  return g_afTacticalNavyDamageScaleByUnitType[unitTypeC];
}
