#pragma once

#include "compat.h"

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640060
class TCouncilPanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TCouncilPanelView)
  virtual ~TCouncilPanelView() override;
  virtual void Draw(RECT* rectBuffer) override;

  TCouncilPanelView();
};
ASSERT_SIZE(TCouncilPanelView, 0x64);
