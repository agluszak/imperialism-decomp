#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657740
class TLonelyTileView : public TView {
public:
  DECLARE_DYNCREATE(TLonelyTileView)
  virtual ~TLonelyTileView() override;
  virtual void Draw(RECT* rectBuffer) override;
  short tileIndex; // tile index passed to the tile-sprite-variant lookup

  TLonelyTileView();
  void SetTile(short tileIndex);
};
ASSERT_SIZE(TLonelyTileView, 0x64);
