#pragma once

#include "compat.h"

#include "game/military_ui/TCheater.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f050
class TGPCheater : public TCheater {
public:
  DECLARE_DYNCREATE(TGPCheater)
  virtual ~TGPCheater() override;

  // NOOP: verified empty in original 0x004b19e3
  TGPCheater() {}

  void ConstructNumericEntryDialogCoreAndValueLabel(int* offsetLayout, int fieldIndex, short value,
                                                    int fieldTag);

  void IGPCheater(TView* panel);

  void DisplayGP(int nationSlot);
};
ASSERT_SIZE(TGPCheater, 0x64);
