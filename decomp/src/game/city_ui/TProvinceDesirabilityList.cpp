#include "game/city_ui/TProvinceDesirabilityList.h"
#include "game/mfc.h"

#include <stdlib.h>

IMPLEMENT_DYNCREATE(TProvinceDesirabilityList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x004d6590
TProvinceDesirabilityList::TProvinceDesirabilityList() {}

// FUNCTION: IMPERIALISM 0x004d6610
void TProvinceDesirabilityList::IProvinceDesirabilityList() {
  recordSize = 4;
}

// FUNCTION: IMPERIALISM 0x004d6630
short TProvinceDesirabilityList::Compare(void* a, void* b) {
  short aKey = static_cast<short*>(a)[1];
  short bKey = static_cast<short*>(b)[1];
  if (bKey < aKey) {
    return 1;
  }
  if (aKey < bKey) {
    return -1;
  }
  return static_cast<short>(rand() % 2 != 0 ? 1 : -1);
}
