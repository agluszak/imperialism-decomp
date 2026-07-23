#pragma once

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063fc68
class TTradePanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TTradePanelView)
  virtual ~TTradePanelView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f8dd0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4f8780
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4f8940
  virtual void Setup() override;                // slot 0x68 0x4f8d50

  TTradePanelView();
};
