#pragma once

#include "compat.h"
#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e4f0
class TTradeBidNationLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTradeBidNationLine)
  virtual ~TTradeBidNationLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5bda20

  // Set directly (not via a method) by TTradePageBuyView::RebuildNationBidRowsForCategory
  // right after construction: categorySlot is the row-building category argument (constant
  // across every row built in one rebuild pass), nationSlot is the per-row nation index.
  short categorySlot; // 0x10
  short nationSlot;   // 0x12

  // NOOP: verified empty in original 0x005bd983 (no standalone TTradeBidNationLine::TTradeBidNationLine body exists: CreateObject 0x005bd950 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TTradeBidNationLine() {}

  // Two-phase init (MacApp IViewClass idiom). Unlike the other line initialisers this
  // one takes its two slot ids FIRST and the shared row/bounds triple after.
  // 0x005bd9e0, __thiscall.
  void ITradeBidNationLine(short categorySlot, short nationSlot, short rowArg, short colArg,
                           int* bounds);
};

ASSERT_SIZE(TTradeBidNationLine, 0x14);
