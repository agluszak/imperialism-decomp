#pragma once

#include "compat.h"
#include "game/city_ui/TBuildingView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006518e8
class TUnitsView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TUnitsView)
  virtual ~TUnitsView() override;
  virtual void DoStartup() override;

  TUnitsView();
};

ASSERT_SIZE(TUnitsView, 0xa0);
