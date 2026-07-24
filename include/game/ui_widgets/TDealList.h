#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_core/TSortedPtrList.h"

class CArchive;

// Mac oracle: TDealList (a small sorted-ptr-list variant). Instances are held by
// TTradeMgr::categoryRankLists (its ctor installs this vtable, 0x66da38). This is a
// distinct class from the TTradeMgr manager it was previously conflated with.
// VTABLE: IMPERIALISM 0x0066da38
class TDealList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TDealList)
  virtual ~TDealList() override; // slot 0x01 (scalar deleting destructor)
  // Deal-priority comparator: weighted (value * priority) score, inverted for deal
  // kinds 0xd-0x10, with a mod-7 pseudo-random tiebreak over the record fields.
  short Compare(void* a, void* b) override; // slot 0x11 0x5ba260

  TDealList();
};
ASSERT_SIZE(TDealList, 0x18);
