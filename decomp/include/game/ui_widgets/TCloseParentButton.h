#pragma once

#include "compat.h"

#include "game/TButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006648d8
class TCloseParentButton : public TButton {
public:
  DECLARE_DYNCREATE(TCloseParentButton)
  virtual ~TCloseParentButton() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  TCloseParentButton();
};
ASSERT_SIZE(TCloseParentButton, 0x84);
