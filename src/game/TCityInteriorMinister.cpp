#include "game/TCityInteriorMinister.h"

// FUNCTION: IMPERIALISM 0x004be840
TCityInteriorMinister::TCityInteriorMinister() : TMinister() {}

// FUNCTION: IMPERIALISM 0x004be8d0
void TCityInteriorMinister::InitializeCityInteriorState() {
  reinterpret_cast<void(__cdecl*)(TCityInteriorMinister*)>(thunk_InitializeCityInteriorMinister)(this);
}

void TCityInteriorMinister::CityInteriorSlot2C() {}
void TCityInteriorMinister::CityInteriorSlot2D() {}
void TCityInteriorMinister::CityInteriorSlot2E() {}
void TCityInteriorMinister::CityInteriorSlot2F() {}
int TCityInteriorMinister::GetHomeCityRecordIndexSlotC0() { return 0; }
void TCityInteriorMinister::CityInteriorSlot31() {}
void TCityInteriorMinister::CityInteriorSlot32() {}
void TCityInteriorMinister::CityInteriorSlot33() {}
void TCityInteriorMinister::CityInteriorSlot34() {}
void TCityInteriorMinister::CallD4() {}
