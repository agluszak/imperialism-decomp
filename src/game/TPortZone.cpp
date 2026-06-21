#include "game/TPortZone.h"

#include <new.h>

#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" char g_pClassDescTPortZone = 0;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// FUNCTION: IMPERIALISM 0x005615e0
TPortZone* TPortZone::CreateTPortZone() {
  void* allocation = reinterpret_cast<void*>(
      AllocateWithFallbackHandler(static_cast<undefined4>(sizeof(TPortZone))));
  if (allocation == 0) {
    return 0;
  }
  return new (allocation) TPortZone();
}

TPortZone::TPortZone() : TZone() {
  field48 = -1;
}

// FUNCTION: IMPERIALISM 0x00561660
bool TPortZone::QueryZoneCapabilityFlagA() {
  return true;
}

// FUNCTION: IMPERIALISM 0x00561680
bool TPortZone::QueryPortZoneCapability() {
  return true;
}

// FUNCTION: IMPERIALISM 0x005616a0
bool TPortZone::QueryZoneCapabilityFlagC() {
  return false;
}

// 0x005621e0 is TOcean::Free (TPortZone's "vtable" 0x65c7e4 aliases TOcean's
// vtable tail), so it is owned there now. TPortZone's real slot-0 body is a
// separate port; this unmarked GetRuntimeClass stub keeps the class compilable.
CRuntimeClass* TPortZone::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTPortZone);
}
TPortZone::~TPortZone() {}
