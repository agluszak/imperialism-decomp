#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e1f0
class TNavyBoyView : public TView {
public:
  DECLARE_DYNCREATE(TNavyBoyView)
  virtual ~TNavyBoyView() override;
  virtual void Draw(RECT* rectBuffer) override;

  // NOOP: verified empty in original 0x004af003
  TNavyBoyView() {}

  BattleReportDetailRecord* battleDetail;
};
ASSERT_SIZE(TNavyBoyView, 0x64);
