#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bf80
class TMinorTreatyDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorTreatyDialog)
  virtual ~TMinorTreatyDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues();             // slot 0x68 0x5b4090

  // NOOP: verified empty in original 0x005b3fc3 (no standalone TMinorTreatyDialog::TMinorTreatyDialog body exists: CreateObject 0x005b3f90 inlines this default ctor, calling the TView base ctor directly at that site)
  TMinorTreatyDialog() {}
};
ASSERT_SIZE(TMinorTreatyDialog, 0x60);
