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

  TRailheadDialog();

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended at 0x60. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  TCity* city60;
};
ASSERT_SIZE(TRailheadDialog, 0x64);
