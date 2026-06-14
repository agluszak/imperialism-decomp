#include "game/TCityMinisterPersonalities.h"

// FUNCTION: IMPERIALISM 0x004c59e0
TSteelCityMinister::TSteelCityMinister() : TCityInteriorMinister() {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x14) = 1;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x16) = 1;
}

// FUNCTION: IMPERIALISM 0x004c5ce0
TShipBuilderCityMinister::TShipBuilderCityMinister() : TCityInteriorMinister() {}

// FUNCTION: IMPERIALISM 0x004c5fe0
TEvenCityMinister::TEvenCityMinister() : TCityInteriorMinister() {}

// FUNCTION: IMPERIALISM 0x004c62f0
TRailCityMinister::TRailCityMinister() : TCityInteriorMinister() {}
