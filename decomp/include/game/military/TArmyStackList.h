#pragma once

#include "compat.h"

#include "game/ui_core/TSortedList.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c9a0
class TArmyStackList : public TSortedList {
public:
  DECLARE_DYNCREATE(TArmyStackList)
  virtual ~TArmyStackList() override;
  short Compare(void* a, void* b) override;

  TArmyStackList() : TSortedList() {}
};
ASSERT_SIZE(TArmyStackList, 0x20);
