#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00644ba0
class TGWorldPartView : public TView {
public:
  DECLARE_DYNCREATE(TGWorldPartView)
  virtual ~TGWorldPartView() override;
  virtual void Draw(RECT* rectBuffer) override;

  TGWorldPartView();

  void SetSourceRectFromGridCell(int column, int row);

  TQuickDrawSurfaceContext* sourceSurface; // ctor 0x45b000 zeroes it
  RECT sourceRect;
};
ASSERT_SIZE(TGWorldPartView, 0x74);
