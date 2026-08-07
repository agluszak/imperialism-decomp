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
  // NOOP: verified empty in original 0x00487e91 (no standalone TList::TList body exists: CreateObject 0x00487e50 inlines this default ctor, calling the CPtrList base ctor directly at that site)
  DECLARE_DYNCREATE(TList)
  // NOOP: verified empty in original (the ctor chain is just TSortedList's; inline so
  // construction sites match the original's fully inlined new-expressions).
  TList() {}
};

ASSERT_SIZE(TList, 0x20);
