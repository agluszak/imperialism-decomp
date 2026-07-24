#pragma once

#include "compat.h"

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063fa70
class TGrantsView : public TPanelView {
public:
  DECLARE_DYNCREATE(TGrantsView)
  virtual ~TGrantsView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f8650
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4f8080
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4f81c0
  virtual void Setup() override;                // slot 0x68 0x4f85d0

  TGrantsView();
};
ASSERT_SIZE(TGrantsView, 0x64);
