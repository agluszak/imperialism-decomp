#include "game/city_ui/TCityMinisterPersonalities.h"

#include "game/city_ui/TLongintList.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TSteelCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c59e0
TSteelCityMinister::TSteelCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// FUNCTION: IMPERIALISM 0x004c5a70
void TSteelCityMinister::ISteelCityMinister(TGreatPower* owner) {
  TCityInteriorMinister::InitializeCityInteriorState(owner);
}

// FUNCTION: IMPERIALISM 0x004c5a90
void TSteelCityMinister::FillLists() {
  manufacturingPriority->InsertLast(15);
  manufacturingPriority->InsertLast(16);
  manufacturingPriority->InsertLast(11);
  manufacturingPriority->InsertLast(14);
  manufacturingPriority->InsertLast(9);
  manufacturingPriority->InsertLast(12);
  manufacturingPriority->InsertLast(13);
  manufacturingPriority->InsertLast(8);

  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(1);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
}

IMPLEMENT_DYNCREATE(TShipBuilderCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c5ce0
TShipBuilderCityMinister::TShipBuilderCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// FUNCTION: IMPERIALISM 0x004c5d70
void TShipBuilderCityMinister::IShipBuilderCityMinister(TGreatPower* owner) {
  TCityInteriorMinister::InitializeCityInteriorState(owner);
}

// FUNCTION: IMPERIALISM 0x004c5d90
void TShipBuilderCityMinister::FillLists() {
  manufacturingPriority->InsertLast(14);
  manufacturingPriority->InsertLast(9);
  manufacturingPriority->InsertLast(15);
  manufacturingPriority->InsertLast(16);
  manufacturingPriority->InsertLast(11);
  manufacturingPriority->InsertLast(12);
  manufacturingPriority->InsertLast(13);
  manufacturingPriority->InsertLast(8);

  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(1);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(1);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
}

IMPLEMENT_DYNCREATE(TEvenCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c5fe0
TEvenCityMinister::TEvenCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// FUNCTION: IMPERIALISM 0x004c6070
void TEvenCityMinister::IEvenCityMinister(TGreatPower* owner) {
  TCityInteriorMinister::InitializeCityInteriorState(owner);
}

// FUNCTION: IMPERIALISM 0x004c6090
void TEvenCityMinister::FillLists() {
  manufacturingPriority->InsertLast(15);
  manufacturingPriority->InsertLast(16);
  manufacturingPriority->InsertLast(13);
  manufacturingPriority->InsertLast(14);
  manufacturingPriority->InsertLast(9);
  manufacturingPriority->InsertLast(11);
  manufacturingPriority->InsertLast(8);
  manufacturingPriority->InsertLast(12);

  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(1);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(1);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(0);
}

IMPLEMENT_DYNCREATE(TRailCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c62f0
TRailCityMinister::TRailCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// FUNCTION: IMPERIALISM 0x004c6380
void TRailCityMinister::IRailCityMinister(TGreatPower* owner) {
  TCityInteriorMinister::InitializeCityInteriorState(owner);
}

// FUNCTION: IMPERIALISM 0x004c63a0
void TRailCityMinister::FillLists() {
  manufacturingPriority->InsertLast(14);
  manufacturingPriority->InsertLast(9);
  manufacturingPriority->InsertLast(15);
  manufacturingPriority->InsertLast(16);
  manufacturingPriority->InsertLast(11);
  manufacturingPriority->InsertLast(12);
  manufacturingPriority->InsertLast(13);
  manufacturingPriority->InsertLast(8);

  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(0);
  buildingUpgradePriority->InsertLast(1);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(2);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(5);
  buildingUpgradePriority->InsertLast(3);
  buildingUpgradePriority->InsertLast(4);
  buildingUpgradePriority->InsertLast(2);
}
