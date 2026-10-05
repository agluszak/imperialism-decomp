#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e958
class TTradeTotalsView : public TView {
public:
  DECLARE_DYNCREATE(TTradeTotalsView)
  virtual ~TTradeTotalsView() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5c1bd0

  TTradeTotalsView();

  void ITradeTotalsView(TView* panel, int* offsetLayout, int* sizeLayout, short nation); // 0x5c1b90

  short nationSlot;
  short unused62;
};
ASSERT_SIZE(TTradeTotalsView, 0x64);
