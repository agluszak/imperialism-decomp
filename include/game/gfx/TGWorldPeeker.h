#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00656748
class TGWorldPeeker : public TView {
public:
  DECLARE_DYNCREATE(TGWorldPeeker)
  virtual ~TGWorldPeeker() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4ff2f0

  TGWorldPeeker();

  // Source surface; Draw blits the whole passed-in rect from it 1:1
  // (source and destination rect are the same RECT).
  TQuickDrawSurfaceContext* field60;
};
