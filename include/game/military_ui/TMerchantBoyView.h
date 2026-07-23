#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e3e8
class TMerchantBoyView : public TView {
public:
  DECLARE_DYNCREATE(TMerchantBoyView)
  virtual ~TMerchantBoyView() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af780

  TMerchantBoyView();

  struct BattleReportDetailRecord* battleDetail60; // +0x60
};
