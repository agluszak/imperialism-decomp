#include "game/TCityInteriorMinister.h"

#include "game/mfc.h"

extern "C" {
CRuntimeClass g_pClassDescTCityInteriorMinister = {nullptr, 0, 0, nullptr, nullptr};
}

// NOTE: The city-policy virtual run (slots 0x58-0xd4) — production rebalancing, command
// queueing, home-tile selection, neighbor-bucket rebuilds — is promoted here as a real
// virtual override layout owning the original addresses (previously return-0 autogen
// stubs / orphan leaves). Bodies are honest partial ports to be enriched later; the slot
// ownership is what drives vtable matching. Methods are listed in ascending-address order
// (marker hygiene), which differs from slot order.

// FUNCTION: IMPERIALISM 0x004be480
void TCityInteriorMinister::CityInteriorSlot16() {}

// FUNCTION: IMPERIALISM 0x004be4c0
void TCityInteriorMinister::CityInteriorSlot17() {}

// FUNCTION: IMPERIALISM 0x004be650
void TCityInteriorMinister::CityInteriorSlot18() {}

// FUNCTION: IMPERIALISM 0x004be690
void TCityInteriorMinister::CityInteriorSlot19() {}

// FUNCTION: IMPERIALISM 0x004be7b0
void TCityInteriorMinister::CityInteriorSlot1D() {}

// FUNCTION: IMPERIALISM 0x004be7d0
void TCityInteriorMinister::CityInteriorSlot1E() {}

// FUNCTION: IMPERIALISM 0x004be7f0
void TCityInteriorMinister::CityInteriorSlot1F() {}

// FUNCTION: IMPERIALISM 0x004be820
CRuntimeClass* TCityInteriorMinister::GetRuntimeClass() const {
  return &g_pClassDescTCityInteriorMinister;
}

// FUNCTION: IMPERIALISM 0x004be840
TCityInteriorMinister::TCityInteriorMinister() : TInteriorMinister() {}

// SYNTHETIC: IMPERIALISM 0x004be880
// TCityInteriorMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004be8d0
void TCityInteriorMinister::InitializeCityInteriorState() {
  reinterpret_cast<void(__cdecl*)(TCityInteriorMinister*)>(thunk_InitializeCityInteriorMinister)(
      this);
}

// FUNCTION: IMPERIALISM 0x004becd0
void TCityInteriorMinister::Free() {}

// FUNCTION: IMPERIALISM 0x004bed60
void TCityInteriorMinister::CityInteriorSlot20() {}

// FUNCTION: IMPERIALISM 0x004bee20
void TCityInteriorMinister::MinisterSlot0A() {}

// FUNCTION: IMPERIALISM 0x004beeb0
void TCityInteriorMinister::CityInteriorSlot1A() {}

// FUNCTION: IMPERIALISM 0x004beee0
void TCityInteriorMinister::CityInteriorSlot1B() {}

// FUNCTION: IMPERIALISM 0x004bef10
void TCityInteriorMinister::CityInteriorSlot2D() {}

// FUNCTION: IMPERIALISM 0x004bef30
void TCityInteriorMinister::CityInteriorSlot1C() {}

// FUNCTION: IMPERIALISM 0x004bef60
void TCityInteriorMinister::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x004bf390
void TCityInteriorMinister::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x004bf770
void TCityInteriorMinister::Call54() {}

// FUNCTION: IMPERIALISM 0x004bf8a0
void TCityInteriorMinister::CityInteriorSlot21() {}

// FUNCTION: IMPERIALISM 0x004bfa50
void TCityInteriorMinister::CityInteriorSlot22() {}

// FUNCTION: IMPERIALISM 0x004bfb20
void TCityInteriorMinister::CityInteriorSlot23() {}

// FUNCTION: IMPERIALISM 0x004bff60
void TCityInteriorMinister::CityInteriorSlot24() {}

// FUNCTION: IMPERIALISM 0x004bff80
void TCityInteriorMinister::CityInteriorSlot2B() {}

// FUNCTION: IMPERIALISM 0x004c0090
void TCityInteriorMinister::CityInteriorSlot26() {}

// FUNCTION: IMPERIALISM 0x004c02c0
void TCityInteriorMinister::CityInteriorSlot25() {}

// FUNCTION: IMPERIALISM 0x004c04e0
void TCityInteriorMinister::CityInteriorSlot27() {}

// FUNCTION: IMPERIALISM 0x004c05a0
void TCityInteriorMinister::CityInteriorSlot28() {}

// FUNCTION: IMPERIALISM 0x004c0690
void TCityInteriorMinister::CityInteriorSlot29() {}

// FUNCTION: IMPERIALISM 0x004c0730
void TCityInteriorMinister::CityInteriorSlot2A() {}

// FUNCTION: IMPERIALISM 0x004c07d0
void TCityInteriorMinister::CityInteriorSlot2C() {}

// FUNCTION: IMPERIALISM 0x004c0d90
void TCityInteriorMinister::NotifySlot44(void* receiver) {
  (void)receiver;
}

// FUNCTION: IMPERIALISM 0x004c0de0
void TCityInteriorMinister::CityInteriorSlot2E() {}

// FUNCTION: IMPERIALISM 0x004c0e50
void TCityInteriorMinister::CityInteriorSlot2F() {}

// FUNCTION: IMPERIALISM 0x004c11c0
int TCityInteriorMinister::GetHomeCityRecordIndexSlotC0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004c1510
void TCityInteriorMinister::CallD4() {}

// FUNCTION: IMPERIALISM 0x004c1ac0
void TCityInteriorMinister::CityInteriorSlot31() {}

// FUNCTION: IMPERIALISM 0x004c2010
void TCityInteriorMinister::CityInteriorSlot32() {}

// FUNCTION: IMPERIALISM 0x004c2120
void TCityInteriorMinister::CityInteriorSlot33() {}

// FUNCTION: IMPERIALISM 0x004c2a30
void TCityInteriorMinister::CityInteriorSlot34() {}
