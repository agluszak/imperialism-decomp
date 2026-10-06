#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"

struct TQuickDrawSurfaceContext;

// Engineer-dialog view (university advanced status UI). Mac: TEngineerDialog::Free, Draw.
// VTABLE: IMPERIALISM 0x652d60
class TEngineerDialog : public TView {
public:
  TQuickDrawSurfaceContext* headerSurface;   // 0x60
  TQuickDrawSurfaceContext* footerSurface;   // 0x64
  TQuickDrawSurfaceContext* bodyTileSurface; // 0x68

  TEngineerDialog();
  virtual ~TEngineerDialog() override;

  DECLARE_DYNCREATE(TEngineerDialog)
  void Free() override;                 // 0x1c 0x4d05e0
  void Draw(RECT* rectBuffer) override; // 0x110 0x4d0650

  virtual void StuffValues(short nBuildingSlotId); // slot 0x68
};
ASSERT_SIZE(TEngineerDialog, 0x6c);
