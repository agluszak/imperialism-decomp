#include "game/TProvinceDesirabilityList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTProvinceDesirabilityList = 0;
}

// FUNCTION: IMPERIALISM 0x004d6500
TProvinceDesirabilityList* TProvinceDesirabilityList::CreateTProvinceDesirabilityListInstance() {
  return new TProvinceDesirabilityList();
}

// FUNCTION: IMPERIALISM 0x004d6570
void* TProvinceDesirabilityList::GetTProvinceDesirabilityListClassNamePointer() {
  return &g_pClassDescTProvinceDesirabilityList;
}

// FUNCTION: IMPERIALISM 0x004d6590
TProvinceDesirabilityList::TProvinceDesirabilityList() : TIndexAndRankList(), relationType(0), pad16(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004d65c0
// TProvinceDesirabilityList::`scalar deleting destructor'
