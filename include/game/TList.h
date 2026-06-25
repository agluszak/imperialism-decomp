#pragma once

#include "compat.h"
#include "game/TPtrList.h"

// Concrete game list leaf: TObject vfptr at +0, CPtrList state at +4 through
// TPtrList, and the TList virtual interface (vtable 0x648f78).
// VTABLE: IMPERIALISM 0x00648f78
struct TList : public TPtrList {
  CRuntimeClass* GetRuntimeClass() const override;
  TList() {}

  static TList* CreateTListInstance();
};

ASSERT_SIZE(TList, 0x20);
