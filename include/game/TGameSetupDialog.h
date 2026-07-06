#pragma once

#include "game/TDialogView.h"
#include "game/mfc.h"

// TODO(manifest): describe TGameSetupDialog and its role. Base edge (TDialogView) recovered from RTTI CRuntimeClass chain: TGameSetupDialog -> TDialogView -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066b380
class TGameSetupDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TGameSetupDialog)
  ~TGameSetupDialog() override;

  virtual undefined OrphanRetStub_005b2860();

  TGameSetupDialog();
};

