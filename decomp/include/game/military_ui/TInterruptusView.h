#pragma once

#include "compat.h"

#include "game/military_ui/TItemBoyView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e7d8
class TInterruptusView : public TItemBoyView {
public:
  DECLARE_DYNCREATE(TInterruptusView)
  virtual ~TInterruptusView() override;
  virtual void Draw(RECT* rectBuffer) override;

  // NOOP: verified empty in original 0x004afcf3
  TInterruptusView() {}
};
ASSERT_SIZE(TInterruptusView, 0x64);
