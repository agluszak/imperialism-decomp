#include "game/TCityMinisterPersonalities.h"

#include "game/mfc.h"

extern "C" {
CRuntimeClass g_pClassDescTSteelCityMinister = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass g_pClassDescTShipBuilderCityMinister = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass g_pClassDescTEvenCityMinister = {nullptr, 0, 0, nullptr, nullptr};
CRuntimeClass g_pClassDescTRailCityMinister = {nullptr, 0, 0, nullptr, nullptr};
}

// Each derived city minister overrides only GetRuntimeClass, the scalar deleting
// destructor, and the slot-0x80 priority-preset hook (CityInteriorSlot20). The preset
// bodies are honest partial ports (previously return-0 autogen stubs).

// FUNCTION: IMPERIALISM 0x004c59c0
CRuntimeClass* TSteelCityMinister::GetRuntimeClass() const {
  return &g_pClassDescTSteelCityMinister;
}

// FUNCTION: IMPERIALISM 0x004c59e0
TSteelCityMinister::TSteelCityMinister() : TCityInteriorMinister() {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x14) = 1;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x16) = 1;
}

// SYNTHETIC: IMPERIALISM 0x004c5a20
// TSteelCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c5a90
void TSteelCityMinister::CityInteriorSlot20() {}

// FUNCTION: IMPERIALISM 0x004c5cc0
CRuntimeClass* TShipBuilderCityMinister::GetRuntimeClass() const {
  return &g_pClassDescTShipBuilderCityMinister;
}

// FUNCTION: IMPERIALISM 0x004c5ce0
TShipBuilderCityMinister::TShipBuilderCityMinister() : TCityInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004c5d20
// TShipBuilderCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c5d90
void TShipBuilderCityMinister::CityInteriorSlot20() {}

// FUNCTION: IMPERIALISM 0x004c5fc0
CRuntimeClass* TEvenCityMinister::GetRuntimeClass() const {
  return &g_pClassDescTEvenCityMinister;
}

// FUNCTION: IMPERIALISM 0x004c5fe0
TEvenCityMinister::TEvenCityMinister() : TCityInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004c6020
// TEvenCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c6090
void TEvenCityMinister::CityInteriorSlot20() {}

// FUNCTION: IMPERIALISM 0x004c62d0
CRuntimeClass* TRailCityMinister::GetRuntimeClass() const {
  return &g_pClassDescTRailCityMinister;
}

// FUNCTION: IMPERIALISM 0x004c62f0
TRailCityMinister::TRailCityMinister() : TCityInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004c6330
// TRailCityMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004c63a0
void TRailCityMinister::CityInteriorSlot20() {}
