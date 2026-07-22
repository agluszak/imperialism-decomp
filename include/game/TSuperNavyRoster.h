#pragma once

#include "game/TPageView.h"
#include "game/mfc.h"

class TTaskForce;
class TZone;

// VTABLE: IMPERIALISM 0x0065d910
class TSuperNavyRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperNavyRoster)
  virtual ~TSuperNavyRoster() override; // slot 0x01 (scalar deleting destructor)
  virtual void PopulateNavyOrderPageEntriesByMapContext(TView* panel, int* offsetLayout,
                                                        int* sizeLayout); // slot 0x6e 0x5698e0

  // A TMiniShipView row click returns either the loose ship's zone or its existing task
  // force. The dialog driver applies exactly one of these after the modal closes.
  TZone* selectedZone84;
  TTaskForce* selectedTaskForce88;

  // The original constructor is inline-expanded at callers: base page construction,
  // own vptr, then both selection outputs are cleared.
  TSuperNavyRoster() : TPageView(), selectedZone84(0), selectedTaskForce88(0) {}
};

ASSERT_SIZE(TSuperNavyRoster, 0x8c);
