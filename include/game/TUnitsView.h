#pragma once

#include "compat.h"
#include "game/TBuildingView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006518e8
class TUnitsView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TUnitsView)
  virtual ~TUnitsView() override;    // slot 0x01 (scalar deleting destructor)
  virtual void DoStartup() override; // slot 0x75 0x4c8050
  // RTTI oracle: sizeof(TUnitsView) == 0xa0, identical to TBuildingView -- this class
  // adds no data members of its own; its ctor (0x4c7fd0) only installs its own vtable
  // over the inlined TBuildingView base construction.

  TUnitsView();
};

ASSERT_SIZE(TUnitsView, 0xa0);
