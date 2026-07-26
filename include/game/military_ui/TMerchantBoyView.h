#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e3e8
class TMerchantBoyView : public TView {
public:
  DECLARE_DYNCREATE(TMerchantBoyView)
  virtual ~TMerchantBoyView() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af780

  // NOOP: verified empty in original 0x004af6d3 (no standalone TMerchantBoyView::TMerchantBoyView body exists: CreateObject 0x004af6a0 inlines this default ctor, calling the TView base ctor directly at that site)
  TMerchantBoyView() {}

  BattleReportDetailRecord* battleDetail60; // +0x60
};
ASSERT_SIZE(TMerchantBoyView, 0x64);
