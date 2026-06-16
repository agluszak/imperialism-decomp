#include "game/TProvinceDesirabilityList.h"
#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTProvinceDesirabilityList = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x004d6500
TProvinceDesirabilityList* TProvinceDesirabilityList::CreateTProvinceDesirabilityListInstance() {
  return new TProvinceDesirabilityList();
}

// FUNCTION: IMPERIALISM 0x004d6570
CRuntimeClass* TProvinceDesirabilityList::GetRuntimeClass() const {
  return &g_pClassDescTProvinceDesirabilityList;
}

// FUNCTION: IMPERIALISM 0x004d6590
TProvinceDesirabilityList::TProvinceDesirabilityList()
    : TIndexAndRankList(), relationType(0), pad16(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004d65c0
// TProvinceDesirabilityList::`scalar deleting destructor'
