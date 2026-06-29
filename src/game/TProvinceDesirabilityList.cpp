#include "game/TProvinceDesirabilityList.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TProvinceDesirabilityList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x004d6500
TProvinceDesirabilityList* TProvinceDesirabilityList::CreateTProvinceDesirabilityListInstance() {
  return new TProvinceDesirabilityList();
}

// FUNCTION: IMPERIALISM 0x004d6590
TProvinceDesirabilityList::TProvinceDesirabilityList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004d65c0
// TProvinceDesirabilityList::`scalar deleting destructor'
