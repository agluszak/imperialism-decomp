#include "game/TStationedUnitNode.h"

extern "C" short g_awTacticalUnitCategoryCodeBySlot[];

// FUNCTION: IMPERIALISM 0x005c3490
short TStationedUnitNode::GetUnitMovementClassId() {
  return g_awTacticalUnitCategoryCodeBySlot[this->unitTypeId04];
}
