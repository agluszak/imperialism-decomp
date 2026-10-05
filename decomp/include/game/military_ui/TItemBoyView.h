#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e5e0
class TItemBoyView : public TView {
public:
  DECLARE_DYNCREATE(TItemBoyView)
  virtual ~TItemBoyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af9f0

  // NOOP: verified empty in original 0x004af943 (no standalone TItemBoyView::TItemBoyView body exists: CreateObject 0x004af910 inlines this default ctor, calling the TView base ctor directly at that site)
  TItemBoyView() {}

  void ActuallyDraw(CString* header);

  BattleReportDetailRecord* battleDetail; // +0x60
};
ASSERT_SIZE(TItemBoyView, 0x64);
