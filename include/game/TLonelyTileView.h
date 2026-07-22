#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657740
class TLonelyTileView : public TView {
public:
  DECLARE_DYNCREATE(TLonelyTileView)
  virtual ~TLonelyTileView() override;          // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x505b60
  short tileIndex60; // +0x60 tile index passed to the tile-sprite-variant lookup

  TLonelyTileView();
};
