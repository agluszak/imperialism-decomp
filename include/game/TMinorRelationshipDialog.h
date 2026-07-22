#pragma once

#include "game/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bb90
class TMinorRelationshipDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorRelationshipDialog)
  virtual ~TMinorRelationshipDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;                // slot 0x28 0x5b3400
  virtual undefined VTableSlot68();             // slot 0x68 0x5b3570

  TMinorRelationshipDialog();
};
