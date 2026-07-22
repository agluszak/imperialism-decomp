#pragma once

#include "game/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640060
class TCouncilPanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TCouncilPanelView)
  virtual ~TCouncilPanelView() override;        // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4fb030

  TCouncilPanelView();
};
