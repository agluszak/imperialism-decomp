#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645ab0
class TTechHistoryView : public TView {
public:
  DECLARE_DYNCREATE(TTechHistoryView)
  virtual ~TTechHistoryView() override; // slot 0x01 (scalar deleting destructor)

  TTechHistoryView();

  // Non-virtual (real address 0x5b22c0, called directly, not through the vtable).
  void ConstructTTechHistoryViewBaseState(short techId);
};
