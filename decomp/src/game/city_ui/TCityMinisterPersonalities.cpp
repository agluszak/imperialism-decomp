#include "game/city_ui/TCityMinisterPersonalities.h"

#include "game/city_ui/TLongintList.h"
#include "game/mfc.h"

// Each derived city minister overrides only GetRuntimeClass, the scalar deleting
// destructor, and the slot-0x80 priority-preset hook (FillLists).

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
  list28->InsertLast(15);
  list28->InsertLast(16);
  list28->InsertLast(11);
  list28->InsertLast(14);
  list28->InsertLast(9);
  list28->InsertLast(12);
  list28->InsertLast(13);
  list28->InsertLast(8);

  list2c->InsertLast(0);
  list2c->InsertLast(0);
  list2c->InsertLast(1);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(5);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(5);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
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
  list28->InsertLast(14);
  list28->InsertLast(9);
  list28->InsertLast(15);
  list28->InsertLast(16);
  list28->InsertLast(11);
  list28->InsertLast(12);
  list28->InsertLast(13);
  list28->InsertLast(8);

  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(5);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(0);
  list2c->InsertLast(0);
  list2c->InsertLast(1);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(5);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(0);
  list2c->InsertLast(0);
  list2c->InsertLast(1);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
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
  list28->InsertLast(15);
  list28->InsertLast(16);
  list28->InsertLast(13);
  list28->InsertLast(14);
  list28->InsertLast(9);
  list28->InsertLast(11);
  list28->InsertLast(8);
  list28->InsertLast(12);

  list2c->InsertLast(4);
  list2c->InsertLast(2);
  list2c->InsertLast(0);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
  list2c->InsertLast(0);
  list2c->InsertLast(3);
  list2c->InsertLast(1);
  list2c->InsertLast(5);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
  list2c->InsertLast(0);
  list2c->InsertLast(3);
  list2c->InsertLast(1);
  list2c->InsertLast(5);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
  list2c->InsertLast(0);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
  list2c->InsertLast(0);
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
  list28->InsertLast(14);
  list28->InsertLast(9);
  list28->InsertLast(15);
  list28->InsertLast(16);
  list28->InsertLast(11);
  list28->InsertLast(12);
  list28->InsertLast(13);
  list28->InsertLast(8);

  list2c->InsertLast(0);
  list2c->InsertLast(0);
  list2c->InsertLast(1);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(5);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(4);
  list2c->InsertLast(5);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(2);
  list2c->InsertLast(3);
  list2c->InsertLast(5);
  list2c->InsertLast(3);
  list2c->InsertLast(4);
  list2c->InsertLast(2);
}
