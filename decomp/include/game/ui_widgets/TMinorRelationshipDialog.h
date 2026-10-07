#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bb90
class TMinorRelationshipDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorRelationshipDialog)
  virtual ~TMinorRelationshipDialog() override;
  virtual void Close() override;
  virtual void StuffValues();

  // NOOP: verified empty in original 0x005b3333
  TMinorRelationshipDialog() {}
};
ASSERT_SIZE(TMinorRelationshipDialog, 0x60);
