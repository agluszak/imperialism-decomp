#include "game/TMilitaryUnit.h"

#include "game/global_data_tables.h"

extern "C" short g_awTacticalUnitCategoryCodeBySlot[];

// FUNCTION: IMPERIALISM 0x005c3400
short TMilitaryUnit::GetUnitTypeCostPoints() {
  short unitType = unitTypeId04;
  if (unitType == 0x1b || unitType == 0x1c || unitType == 0x1d) {
    return 1;
  }
  if (g_UnitTypeMilitaryStatTable_00695CD2[unitType][0] == 0x10) {
    return g_UnitTypeMilitaryStatTable_00695CD2[unitType][1];
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c3490
short TMilitaryUnit::GetUnitMovementClassId() {
  return g_awTacticalUnitCategoryCodeBySlot[this->unitTypeId04];
}

// FUNCTION: IMPERIALISM 0x005c34d0
short TMilitaryUnit::IsNotStationedInProvince(short provinceId) {
  return stationedProvinceId06 != provinceId;
}

// FUNCTION: IMPERIALISM 0x005c3530
short TMilitaryUnit::GetUnitTypeStatPercent(short statIndex) {
  return static_cast<short>((g_UnitTypeStatTable_0066EB88[unitTypeId04][statIndex] * 100) /
                            g_UnitTypeStatDivisorTable_0066ED30[statIndex]);
}
