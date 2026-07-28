#pragma once

#include "compat.h"
#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e2b8
class TTradeOfferNationLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeOfferNationLine)
  virtual ~TTradeOfferNationLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5bd090

  // Set directly (not via a method) by TTradePageSellView::RebuildNationOfferRowsForCategory
  // right after construction: categorySlot is the row-building category argument (constant
  // across every row built in one rebuild pass), nationSlot is the per-row nation index.
  short categorySlot; // 0x10
  short nationSlot;   // 0x12

  // NOOP: verified empty in original 0x005bcff3 (no standalone TTradeOfferNationLine::TTradeOfferNationLine body exists: CreateObject 0x005bcfc0 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TTradeOfferNationLine() {}

  // Two-phase init (MacApp IViewClass idiom). Unlike the other line initialisers this
  // one takes its two slot ids FIRST and the shared row/bounds triple after.
  // 0x005bd050, __thiscall.
  void ITradeOfferNationLine(short categorySlot, short nationSlot, short rowArg, short colArg,
                             int* bounds);
};

ASSERT_SIZE(TTradeOfferNationLine, 0x14);
