#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e5e0
class TItemBoyView : public TView {
public:
  DECLARE_DYNCREATE(TItemBoyView)
  virtual ~TItemBoyView() override;
  virtual void Draw(RECT* rectBuffer) override;

  // NOOP: verified empty in original 0x004af943
  TItemBoyView() {}

  void ActuallyDraw(CString* header);

  BattleReportDetailRecord* battleDetail;
};
ASSERT_SIZE(TItemBoyView, 0x64);
