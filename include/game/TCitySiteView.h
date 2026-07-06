#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006591d0
class TCitySiteView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TCitySiteView)
  virtual ~TCitySiteView() override;

  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;
  virtual void OrphanRetStub_005966a0(int arg1) override;
  virtual void OrphanRetStub_00596680(int arg1, int arg2) override;
  virtual undefined ReleaseRuntimeSelectionOwnerAndDestroyObject(int param_1, int param_2,
                                                                 int param_3) override;

  TCitySiteView();
};

