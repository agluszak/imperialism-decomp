#pragma once

#include "compat.h"

#include "game/diplomacy_ui/TMinisterView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00655308
class TForeignMinisterView : public TMinisterView {
public:
  DECLARE_DYNCREATE(TForeignMinisterView)
  virtual ~TForeignMinisterView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004f3050
  virtual void ShowWorldMap();                  // slot 0x6c 0x4f31d0
  virtual void ShowWorldExports();              // slot 0x6d 0x4f3220

  TForeignMinisterView();
};
ASSERT_SIZE(TForeignMinisterView, 0x68);
