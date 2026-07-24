#pragma once

#include "compat.h"

#include "game/military_ui/TCheater.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f050
class TGPCheater : public TCheater {
public:
  DECLARE_DYNCREATE(TGPCheater)
  virtual ~TGPCheater() override; // slot 0x01 (scalar deleting destructor)

  // NOOP: verified empty in original 0x004b19e3 (no standalone TGPCheater::TGPCheater body exists: CreateObject 0x004b19b0 inlines this default ctor, calling the TView base ctor directly at that site)
  TGPCheater() {}

  // Build one numeric-entry row of the GP-cheater dialog: a TNumberText value field (range
  // -30000..3000) plus a TStaticText caption offset 0xac to its right. 0x004b1710.
  void ConstructNumericEntryDialogCoreAndValueLabel(int* offsetLayout, int param2, short value,
                                                    int param4);

  // Two-phase init: chain to TCheater's base frame, add the 'name' caption, then build the
  // five treasury/mercenary/pact/sale/purchase numeric-entry rows. 0x004b1a90.
  void ConstructTGPCheaterBaseState(TView* panel);

  // 0x4b1cb0 -- refresh the GP-cheater dialog's nation value fields from g_apNationStates.
  void RefreshGPCheaterNationValues(int nationSlot);
};
ASSERT_SIZE(TGPCheater, 0x64);
