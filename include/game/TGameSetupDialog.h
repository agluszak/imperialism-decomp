#pragma once

#include "game/TDialogView.h"
#include "game/mfc.h"

// TODO(manifest): describe TGameSetupDialog and its role. Base edge (TDialogView) recovered from RTTI CRuntimeClass chain: TGameSetupDialog -> TDialogView -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066b380
class TGameSetupDialog : public TDialogView {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  ~TGameSetupDialog();

  virtual undefined OrphanRetStub_005b2860();

  TGameSetupDialog();
};

// === BEGIN GENERATED (TGameSetupDialog) — refreshed by `just gen-class TGameSetupDialog`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066b380 (105 slots), object size 0x60, base TDialogView
//   slot 0x00  byte 0x00  0x005b2820  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x005b27d0  override  VTableSlot01
//   slot 0x68  byte 0x1a0  0x005b2860  override  OrphanRetStub_005b2860
// clang-format on
// === END GENERATED (TGameSetupDialog) ===
