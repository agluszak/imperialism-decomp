#pragma once

#include "compat.h"

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f878
class TTreatiesView : public TPanelView {
public:
  DECLARE_DYNCREATE(TTreatiesView)
  virtual ~TTreatiesView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Setup() override;

  TTreatiesView();
};
ASSERT_SIZE(TTreatiesView, 0x64);
