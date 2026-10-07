#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bd88
class TGPTreatyDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TGPTreatyDialog)
  virtual ~TGPTreatyDialog() override;
  virtual void StuffValues();

  // NOOP: verified empty in original 0x005b3b13
  TGPTreatyDialog() {}
};
ASSERT_SIZE(TGPTreatyDialog, 0x60);
