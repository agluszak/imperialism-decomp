#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006594e8
class TMapEditView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TMapEditView)
  virtual ~TMapEditView() override;

  virtual void ForwardParam(int param) override;
  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext) override;
  virtual void HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2) override;
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord,
                                                     int dispatchContext) override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;

  TMapEditView();
};

