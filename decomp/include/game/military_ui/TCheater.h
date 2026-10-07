#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ec60
class TCheater : public TView {
public:
  DECLARE_DYNCREATE(TCheater)
  virtual ~TCheater() override; // slot 0x01 (scalar deleting destructor)
  virtual void ApplyCheats();   // slot 0x68 0x4b1410; Mac symbol oracle

  // NOOP: verified empty in original 0x004b13d3
  TCheater() {}

  void ResizeWindow(const CPoint* size); // 0x004b1670

  void ICheater(TView* panel, int unusedArg);

  int captionStringResourceGroup;
};
ASSERT_SIZE(TCheater, 0x64);
