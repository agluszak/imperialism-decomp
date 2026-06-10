#include "game/TRelationManager.h"

#include "game/TGreatPower.h"

// FUNCTION: IMPERIALISM 0x004b4dc0
// Reads the persisted city production order for a building slot; slot 15 derives
// the value from the owned-region count (quartered, or thirded once status flag 9
// reaches its handled state), floored at 1.
#pragma optimize("y", on)
int TRelationManager::GetBuildingProductionValueBySlot(short buildingSlot) {
  if (buildingSlot != 0xf) {
    return this->productionOrderTable1dc[buildingSlot];
  }
  TGreatPower* owner = this->ownerNationAc;
  if (static_cast<signed char>(owner->serializedStatusFlags[9]) < 0x33) {
    if (owner->ownedRegionList->GetCountOrReleaseSlot28() / 4 > 1) {
      return this->ownerNationAc->ownedRegionList->GetCountOrReleaseSlot28() / 4;
    }
  } else {
    if (owner->ownedRegionList->GetCountOrReleaseSlot28() / 3 > 1) {
      return this->ownerNationAc->ownedRegionList->GetCountOrReleaseSlot28() / 3;
    }
  }
  return 1;
}
#pragma optimize("", on)
