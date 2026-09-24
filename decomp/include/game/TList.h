#pragma once

#include "compat.h"
#include "game/ui_core/TSortedList.h"

// Concrete game list leaf; vtable 0x648f78.
// Base recovered from CRuntimeClass descriptor: TList -> TSortedList -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00648f78
class TList : public TSortedList {
public:
  // FUNCTION: IMPERIALISM 0x004888a0
  ~TList() override {}
  DECLARE_DYNCREATE(TList)
  TList() {} // NOOP: verified empty in original 0x00487e91
};

ASSERT_SIZE(TList, 0x20);
