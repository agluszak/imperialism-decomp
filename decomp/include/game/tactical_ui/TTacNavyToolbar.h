#pragma once

#include "compat.h"

#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/mfc.h"

class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0066a5a0
class TTacNavyToolbar : public TTacticalToolbar {
public:
  DECLARE_DYNCREATE(TTacNavyToolbar)
  virtual ~TTacNavyToolbar() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit) override;
  virtual void UpdateTacticalOtherSideUnitControl(TArmyTacUnit* unit) override;

  // NOOP: verified empty in original 0x005ad067
  TTacNavyToolbar() {}
};
ASSERT_SIZE(TTacNavyToolbar, 0x98);
