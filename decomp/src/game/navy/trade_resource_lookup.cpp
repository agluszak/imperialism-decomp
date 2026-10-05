#include "game/navy/TShip.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00550d80
short TShip::GetTypeFirepower(short shipType) {
  return g_NavyOrderResourceDescriptorTable[shipType].Firepower();
}

// FUNCTION: IMPERIALISM 0x00550db0
short TShip::GetTypeBattleRange(short shipType) {
  return g_NavyOrderResourceDescriptorTable[shipType].BattleRange();
}

// FUNCTION: IMPERIALISM 0x00550de0
short TShip::GetTypeArmor(short shipType) {
  return g_NavyOrderResourceDescriptorTable[shipType].Armor();
}

// FUNCTION: IMPERIALISM 0x00550e10
short TShip::GetTypeHullPoints(short shipType) {
  return g_NavyOrderResourceDescriptorTable[shipType].HullPoints();
}

// FUNCTION: IMPERIALISM 0x00550e40
short TShip::GetTypeBattleSpeed(short shipType) {
  return g_NavyOrderResourceDescriptorTable[shipType].BattleSpeed();
}

// FUNCTION: IMPERIALISM 0x00550ea0
short TShip::GetTypeToolbarSlot(short shipType) {
  return static_cast<short>(g_NavyOrderResourceDescriptorTable[shipType].ToolbarSlot());
}

// FUNCTION: IMPERIALISM 0x00550ed0
short TShip::GetTypeSailingSpeed(short shipType) {
  return g_NavyOrderResourceDescriptorTable[shipType].SailingSpeed();
}

// Generic accessor: reads the low short of the `statColumn`-th 4-byte column in the
// resourceType row (column 0=resolve weight, 1=calculate weight, 2=task-force weight,
// 3=stock cap, 4=navy-priority weight, 5=resource descriptor weight,
// 6=toolbar bucket index, 7=descriptor weight, 8=priority tier) -- matches the original's
// shipyard stat-panel indexing.
// FUNCTION: IMPERIALISM 0x00550f30
short TShip::GetTypeStat(short shipType, short statColumn) {
  return static_cast<short>(
      g_NavyOrderResourceDescriptorTable[shipType].valueByColumn[statColumn]);
}
