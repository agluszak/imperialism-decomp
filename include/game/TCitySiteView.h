#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006591d0
class TCitySiteView : public TMapDialog {
public:
  int field364; // +0x364 — no confirmed reader yet
  // Viewport clamp box consumed by SetMapDialogCellCoordinatesAndRefresh (0x51c320).
  // Not initialized by the ctor (0x51beb0); initialized to an inverted (empty) box
  // (+-1000) by NoOpUiLifecycleHook (0x51bff0), then presumably narrowed by whoever
  // opens the city-site view.
  int minColBound368; // +0x368
  int maxColBound36c; // +0x36c
  int minRowBound370; // +0x370
  int maxRowBound374; // +0x374

  DECLARE_DYNCREATE(TCitySiteView)
  virtual ~TCitySiteView() override;

  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;
  virtual void SetMapViewTileIndex(int arg1) override;
  virtual void SetMapViewCellCoordinates(int arg1, int arg2) override;
  // Clamps the requested cell into the bounds box, then runs the base implementation.
  virtual void SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode) override;

  TCitySiteView();
};

ASSERT_SIZE(TCitySiteView, 0x378);
