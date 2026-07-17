#pragma once

#include "compat.h"
#include "game/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e2b8
class TTradeOfferNationLine : public TLineData {
public:
  // === BEGIN GENERATED DECLS (TTradeOfferNationLine) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTradeOfferNationLine)
  virtual ~TTradeOfferNationLine() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void CreateLineItemView(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5bd090
  // slot 0x0b OrphanRetStub_0056f480 inherited unchanged (0x56f480)
  // === END GENERATED DECLS (TTradeOfferNationLine) ===

  // Set directly (not via a method) by TTradePageSellView::RebuildNationOfferRowsForCategory
  // right after construction: categorySlot10 is the row-building category argument (constant
  // across every row built in one rebuild pass), nationSlot12 is the per-row nation index.
  short categorySlot10; // 0x10
  short nationSlot12;   // 0x12

  TTradeOfferNationLine();
};

ASSERT_SIZE(TTradeOfferNationLine, 0x14);
