#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

class TCity;

// VTABLE: IMPERIALISM 0x0064fe78
class TRailheadDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TRailheadDialog)
  virtual ~TRailheadDialog() override;   // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues(TCity* city); // slot 0x68 0x4bd040
  virtual void DoClosingAction(unsigned long dialogActionTag); // slot 0x69 0x4bd260

  // NOOP: verified empty in original 0x004bcf73
  TRailheadDialog() {}

  TCity* city;
};
ASSERT_SIZE(TRailheadDialog, 0x64);
