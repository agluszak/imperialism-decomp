#pragma once

#include "compat.h"

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063fc68
class TTradePanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TTradePanelView)
  virtual ~TTradePanelView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Setup() override;

  TTradePanelView();
};
ASSERT_SIZE(TTradePanelView, 0x64);
