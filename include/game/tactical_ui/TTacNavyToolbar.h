#pragma once

#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/mfc.h"

class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0066a5a0
class TTacNavyToolbar : public TTacticalToolbar {
public:
  DECLARE_DYNCREATE(TTacNavyToolbar)
  virtual ~TTacNavyToolbar() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005ad1b0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5ad180
  virtual undefined UpdateTacticalCurrentUnitControlAndDialogLabel(
      TTacticalUnit* unit) override;                             // slot 0x73 0x5ad0d0
  virtual undefined TacticalToolbarSlot74(int param_1) override; // slot 0x74 0x5ad0f0

  TTacNavyToolbar();
};
