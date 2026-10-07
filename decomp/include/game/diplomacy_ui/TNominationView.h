#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063ed78
class TNominationView : public TPicture {
public:
  DECLARE_DYNCREATE(TNominationView)
  virtual ~TNominationView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Hilite(); // Mac symbol oracle

  // NOOP: verified empty in original 0x004fb716
  TNominationView() {}
};
ASSERT_SIZE(TNominationView, 0x90);
