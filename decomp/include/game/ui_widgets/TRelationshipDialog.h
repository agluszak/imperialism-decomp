#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b998
class TRelationshipDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TRelationshipDialog)
  virtual ~TRelationshipDialog() override;
  virtual void Close() override;
  virtual void StuffValues();

  // NOOP: verified empty in original 0x005b2cd3
  TRelationshipDialog() {}
};
ASSERT_SIZE(TRelationshipDialog, 0x60);
