#pragma once

#include "compat.h"

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063fa70
class TGrantsView : public TPanelView {
public:
  DECLARE_DYNCREATE(TGrantsView)
  virtual ~TGrantsView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Setup() override;

  TGrantsView();
};
ASSERT_SIZE(TGrantsView, 0x64);
