#pragma once

#include "compat.h"

#include "game/diplomacy_ui/TMinisterView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655308
class TForeignMinisterView : public TMinisterView {
public:
  DECLARE_DYNCREATE(TForeignMinisterView)
  virtual ~TForeignMinisterView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void ShowWorldMap();
  virtual void ShowWorldExports();

  TForeignMinisterView();
};
ASSERT_SIZE(TForeignMinisterView, 0x68);
