#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e1f0
class TNavyBoyView : public TView {
public:
  DECLARE_DYNCREATE(TNavyBoyView)
  virtual ~TNavyBoyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af0b0

  // NOOP: verified empty in original 0x004af003 (no standalone TNavyBoyView::TNavyBoyView body exists: CreateObject 0x004aefd0 inlines this default ctor, calling the TView base ctor directly at that site)
  TNavyBoyView() {}

  struct BattleReportDetailRecord* battleDetail60; // +0x60
};
ASSERT_SIZE(TNavyBoyView, 0x64);
