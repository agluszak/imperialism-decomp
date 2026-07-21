#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006594e8
class TMapEditView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TMapEditView)
  virtual ~TMapEditView() override;

  virtual void ForwardParam(int param) override;
  virtual void DoPostCreate(int arg) override;
  virtual void InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext) override;
  virtual void HandleMapTileClickSetOrderContextAndDispatchEvent79(int arg1, int arg2) override;
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord,
                                                       int dispatchContext) override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;

  TMapEditView();

  // Original object size is 0x370 (CRuntimeClass m_nObjectSize); the source class ended at
  // 0x364. No recovered method currently attributes semantics to this trailing state.
  unsigned char unrecoveredTrailingState[12];
};
