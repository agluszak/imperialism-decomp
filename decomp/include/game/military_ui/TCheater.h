#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ec60
class TCheater : public TView {
public:
  DECLARE_DYNCREATE(TCheater)
  virtual ~TCheater() override;
  virtual void ApplyCheats(); // Mac symbol oracle

  // NOOP: verified empty in original 0x004b13d3
  TCheater() {}

  void ResizeWindow(const CPoint* size);

  void ICheater(TView* panel, int unusedArg);

  int captionStringResourceGroup;
};
ASSERT_SIZE(TCheater, 0x64);
