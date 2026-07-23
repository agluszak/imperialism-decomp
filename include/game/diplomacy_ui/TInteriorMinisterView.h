#pragma once

#include "game/diplomacy_ui/TMinisterView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655720
class TInteriorMinisterView : public TMinisterView {
public:
  DECLARE_DYNCREATE(TInteriorMinisterView)
  virtual ~TInteriorMinisterView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f3710

  TInteriorMinisterView();
};
