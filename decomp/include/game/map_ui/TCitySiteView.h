#pragma once

#include "game/map_ui/TMapDialog.h"
#include "game/mfc.h"

class TTown;

// VTABLE: IMPERIALISM 0x006591d0
class TCitySiteView : public TMapDialog {
public:
  TTown* pendingTown;
  int minColumn;
  int maxColumn;
  int minRow;
  int maxRow;

  DECLARE_DYNCREATE(TCitySiteView)
  virtual ~TCitySiteView() override;

  virtual void DoPostCreate(int arg) override;
  virtual void FrameCursorArea() override;
  virtual void NormalClick(short nTileIndex, int nInputFlags) override;
  virtual void SetMapViewTileIndex(int tileIndex) override;
  virtual void SetMapViewCellCoordinates(int column, int row) override;
  // Clamps the requested cell into the bounds box, then runs the base implementation.
  virtual void SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode) override;

  TCitySiteView();
};

ASSERT_SIZE(TCitySiteView, 0x378);
