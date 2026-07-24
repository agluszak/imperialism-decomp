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

  // NOOP: verified empty in original 0x004afcf3 (no standalone TInterruptusView::TInterruptusView body exists: CreateObject 0x004afcc0 inlines this default ctor, calling the TView base ctor directly at that site)
  TInterruptusView() {}
};
ASSERT_SIZE(TInterruptusView, 0x64);
