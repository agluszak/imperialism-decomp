#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e1f0
class TNavyBoyView : public TView {
public:
  DECLARE_DYNCREATE(TNavyBoyView)
  virtual ~TNavyBoyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af0b0

  TNavyBoyView();

  struct BattleReportDetailRecord* battleDetail60; // +0x60
};
