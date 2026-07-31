#pragma once

#ifndef IMPERIALISM_TRANSPORT_SCREEN_H
#define IMPERIALISM_TRANSPORT_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error TransportScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TTransportPicture;

// The transport ledger.
//
// Its root has no class of its own: the resource builds 'main' as a plain TPicture (the generated
// factory for event 0x07de constructs `new TPicture()`), so unlike every other screen here its
// identity cannot rest on a view class. It rests on the turn event plus the ledger's own controls,
// which is what HasLedgerHeadings() is for -- and why the scenario driving this screen asks
// IsCurrent() rather than naming a class it does not have.
class TransportScreen : public MainViewScreen {
public:
  TransportScreen();

  static bool IsCurrent();

  // Both column headings are present and carry the strings the ledger loads for them.
  bool HasLedgerHeadings() const;
  // The map toolbar's transport button shows its selected artwork and is not left hilited. A
  // question about the toolbar, but only meaningful while this screen is up.
  bool ToolbarIconIsSelected() const;
  // A commodity row's hover help reads as finished text: both of its labelled amounts, and no
  // leftover substitution bracket.
  bool CommodityHelpIsSubstituted(short commodityIndex) const;
  // The capacity readout agrees with the split it is showing, and keeps the geometry the ledger
  // lays it out with -- a label that drifts here overlaps the gauge beside it.
  bool CapacityLabelMatchesSplit() const;
  bool CapacityLabelHasRetailGeometry() const;

  RuntimeActionResult Close();

private:
  TTransportPicture* CapacityGauge() const;
  class TStaticText* CapacityLabel() const;
  class TStaticText* Heading(int tag) const;
};

inline TransportScreen Transport() {
  return TransportScreen();
}

#endif
