#pragma once

#include "game/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f878
class TTreatiesView : public TPanelView {
public:
  DECLARE_DYNCREATE(TTreatiesView)
  virtual ~TTreatiesView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f7f80
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4f7ac0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4f7c00
  virtual void Setup() override;                // slot 0x68 0x4f7f10

  TTreatiesView();
};
