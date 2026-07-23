#pragma once

#include "game/TButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006648d8
class TCloseParentButton : public TButton {
public:
  DECLARE_DYNCREATE(TCloseParentButton)
  virtual ~TCloseParentButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00584d30

  TCloseParentButton();
};
