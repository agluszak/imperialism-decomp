#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00644ba0
class TGWorldPartView : public TView {
public:
  DECLARE_DYNCREATE(TGWorldPartView)
  virtual ~TGWorldPartView() override;          // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4ac880

  TGWorldPartView();

  void SetSourceRectFromGridCell(int column, int row); // 0x577df0

  TQuickDrawSurfaceContext* sourceSurface60; // 0x60 — ctor 0x45b000 zeroes it
  RECT sourceRect64;                         // 0x64
};
ASSERT_SIZE(TGWorldPartView, 0x74);
