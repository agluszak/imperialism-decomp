#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bb90
class TMinorRelationshipDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorRelationshipDialog)
  virtual ~TMinorRelationshipDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;                // slot 0x28 0x5b3400
  virtual void StuffValues();                   // slot 0x68 0x5b3570

  // NOOP: verified empty in original 0x005b3333
  TMinorRelationshipDialog() {}
};
ASSERT_SIZE(TMinorRelationshipDialog, 0x60);
