#pragma once

#include "compat.h"

#include "game/military_ui/TItemBoyView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e7d8
class TInterruptusView : public TItemBoyView {
public:
  DECLARE_DYNCREATE(TInterruptusView)
  virtual ~TInterruptusView() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4afda0

  TInterruptusView();
};
ASSERT_SIZE(TInterruptusView, 0x64);
