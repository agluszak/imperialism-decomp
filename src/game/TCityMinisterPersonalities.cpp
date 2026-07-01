#include "game/TCityMinisterPersonalities.h"

#include "game/mfc.h"

// Each derived city minister overrides only GetRuntimeClass, the scalar deleting
// destructor, and the slot-0x80 priority-preset hook (CityInteriorSlot20). The preset
// bodies are honest partial ports (previously return-0 autogen stubs).
// SYNTHETIC: IMPERIALISM 0x004c5900
// TSteelCityMinister::CreateObject

IMPLEMENT_DYNCREATE(TSteelCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c59e0
TSteelCityMinister::TSteelCityMinister() : TCityInteriorMinister() {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x14) = 1;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x16) = 1;
}

// SYNTHETIC: IMPERIALISM 0x004c5a20
// TSteelCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c5a90
void TSteelCityMinister::CityInteriorSlot20() {}
// SYNTHETIC: IMPERIALISM 0x004c5c00
// TShipBuilderCityMinister::CreateObject

IMPLEMENT_DYNCREATE(TShipBuilderCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c5ce0
TShipBuilderCityMinister::TShipBuilderCityMinister() : TCityInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004c5d20
// TShipBuilderCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c5d90
void TShipBuilderCityMinister::CityInteriorSlot20() {}
// SYNTHETIC: IMPERIALISM 0x004c5f00
// TEvenCityMinister::CreateObject

IMPLEMENT_DYNCREATE(TEvenCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c5fe0
TEvenCityMinister::TEvenCityMinister() : TCityInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004c6020
// TEvenCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c6090
void TEvenCityMinister::CityInteriorSlot20() {}
// SYNTHETIC: IMPERIALISM 0x004c6210
// TRailCityMinister::CreateObject

IMPLEMENT_DYNCREATE(TRailCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c62f0
TRailCityMinister::TRailCityMinister() : TCityInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004c6330
// TRailCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c63a0
void TRailCityMinister::CityInteriorSlot20() {}
