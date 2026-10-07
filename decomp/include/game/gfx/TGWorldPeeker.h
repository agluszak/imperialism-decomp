#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00656748
class TGWorldPeeker : public TView {
public:
  DECLARE_DYNCREATE(TGWorldPeeker)
  virtual ~TGWorldPeeker() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4ff2f0

  TGWorldPeeker() : peekSurface(NULL) {}

  TQuickDrawSurfaceContext* peekSurface;
};
ASSERT_SIZE(TGWorldPeeker, 0x64);
