#pragma once

#include "compat.h"
#include "game/TSortedList.h"

// Concrete game list leaf; vtable 0x648f78.
// Base recovered from CRuntimeClass descriptor: TList -> TSortedList -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00648f78
class TList : public TSortedList {
public:
  DECLARE_DYNCREATE(TList)
  TList();

  static TList* CreateTListInstance();
};

ASSERT_SIZE(TList, 0x20);
