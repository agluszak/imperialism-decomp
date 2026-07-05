#include "game/TArmyStack.h"

#include "game/TMilitaryUnit.h"

// FUNCTION: IMPERIALISM 0x004a3b70
TUnit* TArmyStack::ResetCursorAndGetHeadUnit() {
  this->cursor18 = this->head14;
  return (this->head14 != nullptr) ? this->head14->unit : nullptr;
}

// FUNCTION: IMPERIALISM 0x004a3b90
TUnit* TArmyStack::AdvanceCursorAndGetUnit() {
  if (this->cursor18 != nullptr) {
    this->cursor18 = this->cursor18->next;
    if (this->cursor18 != nullptr) {
      return this->cursor18->unit;
    }
  }
  return nullptr;
}

// SYNTHETIC: IMPERIALISM 0x004a76a0
// TArmyStack::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a76d0
// TArmyStack::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyStack, TObject)

TArmyStack::TArmyStack() {}

// SYNTHETIC: IMPERIALISM 0x004a7720
// TArmyStack::`scalar deleting destructor'
TArmyStack::~TArmyStack() {}

// FUNCTION: IMPERIALISM 0x004a77b0
void TArmyStack::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a7960
void TArmyStack::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004a7c20
void TArmyStack::Free() {}

// FUNCTION: IMPERIALISM 0x004a7e70
void TArmyStack::AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(int* outWeightedSum,
                                                                          int* outCount,
                                                                          int counter) {
  // TODO: port body @ 0x4a7e70 (355 bytes; not yet ported).
  (void)counter;
  *outWeightedSum = 0;
  *outCount = 0;
}

// FUNCTION: IMPERIALISM 0x004a8040
void TArmyStack::ApplyRandomizedMeterDecayToEligibleLinkedEntries(int weightedSum, int count,
                                                                  int counter) {
  // TODO: port body @ 0x4a8040 (482 bytes; not yet ported).
  (void)weightedSum;
  (void)count;
  (void)counter;
}

// FUNCTION: IMPERIALISM 0x004a82b0
void TArmyStack::ApplyMeterGrowthToEligibleUnits(bool boosted) {
  short growthAmount = boosted ? 0x23 : 0x14;
  TUnit* unit = this->ResetCursorAndGetHeadUnit();
  while (unit != nullptr) {
    TMilitaryUnit* milUnit = static_cast<TMilitaryUnit*>(unit);
    if (milUnit->field_34 > 0) {
      milUnit->field_38 = static_cast<short>(milUnit->field_38 + growthAmount);
      if (milUnit->field_38 > 0x190) {
        milUnit->field_38 = 0x190;
      }
    }
    unit = this->AdvanceCursorAndGetUnit();
  }
}
