#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bd88
class TGPTreatyDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TGPTreatyDialog)
  virtual ~TGPTreatyDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues();          // slot 0x68 0x5b3be0

  // NOOP: verified empty in original 0x005b3b13 (no standalone TGPTreatyDialog::TGPTreatyDialog body exists: CreateObject 0x005b3ae0 inlines this default ctor, calling the TView base ctor directly at that site)
  TGPTreatyDialog() {}
};
ASSERT_SIZE(TGPTreatyDialog, 0x60);
