#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

class TCity;

// VTABLE: IMPERIALISM 0x0064fe78
class TRailheadDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TRailheadDialog)
  virtual ~TRailheadDialog() override;
  virtual void StuffValues(TCity* city);
  virtual void DoClosingAction(unsigned long dialogActionTag);

  // NOOP: verified empty in original 0x004bcf73
  TRailheadDialog() {}

  TCity* city;
};
ASSERT_SIZE(TRailheadDialog, 0x64);
