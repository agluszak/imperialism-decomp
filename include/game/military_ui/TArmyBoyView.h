#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064dff8
class TArmyBoyView : public TView {
public:
  DECLARE_DYNCREATE(TArmyBoyView)
  virtual ~TArmyBoyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4aebc0
  BattleReportDetailRecord* battleDetail60;     // +0x60

  // NOOP: verified empty in original 0x004aeb13 (no standalone TArmyBoyView::TArmyBoyView body exists: CreateObject 0x004aeae0 inlines this default ctor, calling the TView base ctor directly at that site)
  TArmyBoyView() {}
};
ASSERT_SIZE(TArmyBoyView, 0x64);
