#include "game/TCityMinisterPersonalities.h"

#include "game/mfc.h"

// Each derived city minister overrides only GetRuntimeClass, the scalar deleting
// destructor, and the slot-0x80 priority-preset hook (CityInteriorSlot20). The preset
// bodies are honest partial ports (previously return-0 autogen stubs).
// SYNTHETIC: IMPERIALISM 0x004c5900
// TSteelCityMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c59c0
// TSteelCityMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSteelCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c59e0
TSteelCityMinister::TSteelCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// SYNTHETIC: IMPERIALISM 0x004c5a20
// TSteelCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c5a90
void TSteelCityMinister::CityInteriorSlot20() {}
// SYNTHETIC: IMPERIALISM 0x004c5c00
// TShipBuilderCityMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c5cc0
// TShipBuilderCityMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipBuilderCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c5ce0
TShipBuilderCityMinister::TShipBuilderCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// SYNTHETIC: IMPERIALISM 0x004c5d20
// TShipBuilderCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c5d90
void TShipBuilderCityMinister::CityInteriorSlot20() {}
// SYNTHETIC: IMPERIALISM 0x004c5f00
// TEvenCityMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c5fc0
// TEvenCityMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEvenCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c5fe0
TEvenCityMinister::TEvenCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// SYNTHETIC: IMPERIALISM 0x004c6020
// TEvenCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c6090
void TEvenCityMinister::CityInteriorSlot20() {}
// SYNTHETIC: IMPERIALISM 0x004c6210
// TRailCityMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004c62d0
// TRailCityMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRailCityMinister, TCityInteriorMinister)

// FUNCTION: IMPERIALISM 0x004c62f0
TRailCityMinister::TRailCityMinister() : TCityInteriorMinister() {
  capabilityFlag14 = 1;
  capabilityFlag16 = 1;
}

// SYNTHETIC: IMPERIALISM 0x004c6330
// TRailCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c63a0
void TRailCityMinister::CityInteriorSlot20() {}
