#pragma once

#include "compat.h"

#include "game/diplomacy_ui/TMinisterView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655720
class TInteriorMinisterView : public TMinisterView {
public:
  DECLARE_DYNCREATE(TInteriorMinisterView)
  virtual ~TInteriorMinisterView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  TInteriorMinisterView();
};
ASSERT_SIZE(TInteriorMinisterView, 0x68);
