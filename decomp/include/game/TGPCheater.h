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

  void ConstructNumericEntryDialogCoreAndValueLabel(int* offsetLayout, int fieldIndex, short value,
                                                    int fieldTag);

  void IGPCheater(TView* panel);

  void DisplayGP(int nationSlot);
};
ASSERT_SIZE(TGPCheater, 0x64);
