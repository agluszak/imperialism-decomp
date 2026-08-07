#pragma once

#include "compat.h"

#include "game/diplomacy_ui/TMinisterView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655518
class TDefenseMinisterView : public TMinisterView {
public:
  DECLARE_DYNCREATE(TDefenseMinisterView)
  virtual ~TDefenseMinisterView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f3370

  TDefenseMinisterView();
};
ASSERT_SIZE(TDefenseMinisterView, 0x68);
