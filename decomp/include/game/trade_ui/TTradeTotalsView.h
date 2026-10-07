#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e958
class TTradeTotalsView : public TView {
public:
  DECLARE_DYNCREATE(TTradeTotalsView)
  virtual ~TTradeTotalsView() override;
  virtual void Draw(RECT* rectBuffer) override;

  TTradeTotalsView();

  void ITradeTotalsView(TView* panel, int* offsetLayout, int* sizeLayout, short nation);

  short nationSlot;
  short unused62;
};
ASSERT_SIZE(TTradeTotalsView, 0x64);
