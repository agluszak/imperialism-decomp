#pragma once

#include "compat.h"

// Compact MacApp-style growable array used as TShortintList's storage base. The
// adjacent one-slot vtables and ProcessUnitOrders' inlined destruction sequence show
// the derived object transitioning to this base before releasing values.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x00650a68
class TShortArrayBase {
public:
  virtual void InsertLast(short value); // slot 0x00 0x4c18a0

  TShortArrayBase() : values(0), capacity(0), count(0) {}
  ~TShortArrayBase();

  short* values;         // +0x04
  unsigned int capacity; // +0x08
  unsigned int count;    // +0x0c
};

ASSERT_SIZE(TShortArrayBase, 0x10);

// Mac oracle type used by the city-interior-minister distance-map and railhead
// selection family. It adds no state or slots to the short-array base.
// VTABLE: IMPERIALISM 0x00650a6c
class TShortintList : public TShortArrayBase {
public:
  TShortintList() : TShortArrayBase() {}
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(TShortintList, 0x10);
