#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_core/TSortedPtrList.h"

class CArchive;

// VTABLE: IMPERIALISM 0x0066da38
class TDealList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TDealList)
  virtual ~TDealList() override; // slot 0x01 (scalar deleting destructor)
  short Compare(void* a, void* b) override; // slot 0x11 0x5ba260

  TDealList();
  void IDealList();
};
ASSERT_SIZE(TDealList, 0x18);
