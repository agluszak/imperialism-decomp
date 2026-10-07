#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064dff8
class TArmyBoyView : public TView {
public:
  DECLARE_DYNCREATE(TArmyBoyView)
  virtual ~TArmyBoyView() override;
  virtual void Draw(RECT* rectBuffer) override;
  BattleReportDetailRecord* battleDetail;

  // NOOP: verified empty in original 0x004aeb13
  TArmyBoyView() {}
};
ASSERT_SIZE(TArmyBoyView, 0x64);
