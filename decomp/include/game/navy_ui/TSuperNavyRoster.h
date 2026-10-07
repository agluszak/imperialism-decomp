#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

class TTaskForce;
class TZone;

// VTABLE: IMPERIALISM 0x0065d910
class TSuperNavyRoster : public TPageView {
public:
  DECLARE_DYNCREATE(TSuperNavyRoster)
  virtual ~TSuperNavyRoster() override;
  virtual void FillNavyPages(TView* panel, int* offsetLayout, int* sizeLayout);

  TZone* selectedZone;
  TTaskForce* selectedTaskForce;

  TSuperNavyRoster() : TPageView(), selectedZone(0), selectedTaskForce(0) {}
};

ASSERT_SIZE(TSuperNavyRoster, 0x8c);
