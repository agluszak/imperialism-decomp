#pragma once

#include "compat.h"

#include "game/diplomacy_ui/TMinisterView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655518
class TDefenseMinisterView : public TMinisterView {
public:
  DECLARE_DYNCREATE(TDefenseMinisterView)
  virtual ~TDefenseMinisterView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  TDefenseMinisterView();
};
ASSERT_SIZE(TDefenseMinisterView, 0x68);
