#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b998
class TRelationshipDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TRelationshipDialog)
  virtual ~TRelationshipDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;           // slot 0x28 0x5b2da0
  // Mac oracle: StuffValues(). Populates the relation-standing matrix cells and
  // the horizontal/vertical nation name labels.
  virtual void StuffValues(); // slot 0x68 0x5b2f10

  TRelationshipDialog();
};
ASSERT_SIZE(TRelationshipDialog, 0x60);
