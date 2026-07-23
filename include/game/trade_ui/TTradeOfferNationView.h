#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e2f8
class TTradeOfferNationView : public TView {
public:
  DECLARE_DYNCREATE(TTradeOfferNationView)
  virtual ~TTradeOfferNationView() override;    // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5bd2d0

  TTradeOfferNationView();

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended
  // at 0x60. The trailing 4 bytes split into two shorts, both read by Draw:
  // +0x60 indexes g_pNationInteractionStateManager->categoryRows[] (a trade-category
  // row) and is the rosterSlot arg to AllocateAndPopulateLinkedValueCollectionFromRosterFilter;
  // +0x62 indexes categoryRows[].cells18[] (a per-nation cell) and is this row's own
  // nation slot (passed to LoadNormalizedCredentialName / the filterValue arg).
  short categorySlot60;
  short nationSlot62;
};
ASSERT_SIZE(TTradeOfferNationView, 0x64);
