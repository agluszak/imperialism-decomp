#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645ab0
class TTechHistoryView : public TView {
public:
  DECLARE_DYNCREATE(TTechHistoryView)
  virtual ~TTechHistoryView() override;

  // NOOP: verified empty in original 0x005b2263
  TTechHistoryView() {}

  // Non-virtual (real address 0x5b22c0, called directly, not through the vtable).
  void StuffValues(short techId);
};
ASSERT_SIZE(TTechHistoryView, 0x60);
