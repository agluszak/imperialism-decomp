#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"

struct TQuickDrawSurfaceContext;

// Engineer-dialog view (university advanced status UI). Mac: TEngineerDialog::Free, Draw.
// VTABLE: IMPERIALISM 0x652d60
class TEngineerDialog : public TView {
public:
  TQuickDrawSurfaceContext* headerSurface;
  TQuickDrawSurfaceContext* footerSurface;
  TQuickDrawSurfaceContext* bodyTileSurface;

  TEngineerDialog();
  virtual ~TEngineerDialog() override;

  DECLARE_DYNCREATE(TEngineerDialog)
  void Free() override;
  void Draw(RECT* rectBuffer) override;

  virtual void StuffValues(short nBuildingSlotId);
};
ASSERT_SIZE(TEngineerDialog, 0x6c);
