#include "game/TProvinceDesirabilityList.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x004d6570
// TProvinceDesirabilityList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProvinceDesirabilityList, TSortedPtrList)

// SYNTHETIC: IMPERIALISM 0x004d6500
// TProvinceDesirabilityList::CreateObject

// FUNCTION: IMPERIALISM 0x004d6590
TProvinceDesirabilityList::TProvinceDesirabilityList() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x004d65c0
// TProvinceDesirabilityList::`scalar deleting destructor'

// Not-yet-recovered free functions this file calls into.
extern undefined4 GenerateThreadLocalRandom15(void);

// FUNCTION: IMPERIALISM 0x004d6630
short TProvinceDesirabilityList::Compare(void* a, void* b) {
  short aKey = *reinterpret_cast<short*>(static_cast<char*>(a) + 2);
  short bKey = *reinterpret_cast<short*>(static_cast<char*>(b) + 2);
  if (bKey < aKey) {
    return 1;
  }
  if (aKey < bKey) {
    return -1;
  }
  return static_cast<short>(static_cast<int>(GenerateThreadLocalRandom15()) % 2 != 0 ? 1 : -1);
}
