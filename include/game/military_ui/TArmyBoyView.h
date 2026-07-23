#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064dff8
class TArmyBoyView : public TView {
public:
  DECLARE_DYNCREATE(TArmyBoyView)
  virtual ~TArmyBoyView() override;                // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override;    // slot 0x44 0x4aebc0
  struct BattleReportDetailRecord* battleDetail60; // +0x60

  TArmyBoyView();
};
