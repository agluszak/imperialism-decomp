#pragma once

#include "compat.h"
#include "game/stretch.h"

// Mac oracle type used by the city-interior-minister distance-map and railhead
// selection family. The adjacent one-slot vtables and ProcessUnitOrders' inlined
// destruction sequence show the derived object transitioning to stretch<short> before
// releasing its backing store.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x00650a6c
class TShortintList : public stretch<short> {
public:
  TShortintList() : stretch<short>() {}
  TShortintList(int initialCapacity) : stretch<short>(initialCapacity) {}
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(TShortintList, 0x10);
