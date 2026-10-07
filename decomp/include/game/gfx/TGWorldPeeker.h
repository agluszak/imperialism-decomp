#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00656748
class TGWorldPeeker : public TView {
public:
  DECLARE_DYNCREATE(TGWorldPeeker)
  virtual ~TGWorldPeeker() override;
  virtual void Draw(RECT* rectBuffer) override;

  TGWorldPeeker() : peekSurface(NULL) {}

  TQuickDrawSurfaceContext* peekSurface;
};
ASSERT_SIZE(TGWorldPeeker, 0x64);
